"""Synthetic reboot/resume, publication and durable GUI request regressions."""
from dataclasses import fields, replace
import errno
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
from types import SimpleNamespace

import pytest

from bfrs.application.scan_config import ScanConfig
from bfrs.application.scan_events import ScanFailedEvent, ScanProgressEvent
from bfrs.application.scan_service import ScanController, ScanService
from bfrs.application.process_scan_runner import ProcessScanRunner
from bfrs.core.source_types import SourceType
from bfrs.gui.scan_jobs import ScanJobStore, encode_config
from bfrs.gui.scan_errors import explain_scan_error


def config(tmp_path, count=25):
    from tests.test_cli import valid_wif
    source = tmp_path/'source'
    source.mkdir()
    for index in range(count):
        (source/f'plik-żółty-{index:03}.bin').write_bytes(valid_wif())
    return ScanConfig(input_path=source, output_path=tmp_path/'raport-żółty.json',
        checkpoint=tmp_path/'checkpoint.sqlite', source_type=SourceType.FOLDER,
        targets=frozenset({'secrets'}), skip_mnemonic=True, chunk_mib=1,
        protect_existing_report=True)


def stop36(value):
    controller = ScanController()
    events = []
    def collect(event):
        events.append(event)
        if isinstance(event, ScanProgressEvent) and event.stage == 'folder-scan' and event.scanned_files >= 9:
            controller.request_stop()
    assert ScanService(controller=controller, event_sink=collect).run(value).exit_code == 130
    with sqlite3.connect(value.checkpoint) as db:
        assert db.execute('SELECT count(*) FROM outcomes').fetchone()[0] == 9
    return events


def protect_committed_rows(path):
    with sqlite3.connect(path) as db:
        db.execute('''CREATE TRIGGER forbid_replay BEFORE INSERT ON outcomes
            WHEN EXISTS(SELECT 1 FROM outcomes WHERE relative_path=NEW.relative_path)
            BEGIN SELECT RAISE(ABORT, 'replayed committed file'); END''')


def test_job_roundtrip_complete_configuration_and_attempt_history(tmp_path):
    value = config(tmp_path)
    value = replace(value, workers=4, file_workers=2, include_bitcoin_context=True,
        minimum_hits=2, padding_mib=3)
    store = ScanJobStore(tmp_path/'jobs')
    first = store.begin(value)
    assert store.load(first.job_id).config == value
    second = store.begin(replace(first.for_resume(), targets=frozenset({'electrum'})))
    store.set_state(second.job_id, 'failed')
    assert store.load(first.job_id).config == value
    assert len(store.incomplete()) == 2
    assert store.load(first.job_id).for_resume().resume_checkpoint == value.checkpoint
    store.complete_checkpoint(second.job_id)
    assert not store.incomplete()
    assert store.load(first.job_id).state=='superseded'
    assert store.load(first.job_id).config.output_path==value.output_path


def test_job_metadata_is_allowlisted_and_never_reads_source_contents(tmp_path, monkeypatch):
    value = config(tmp_path, count=1)
    secret = 'SYNTHETIC_SECRET_MUST_NOT_BE_PERSISTED'
    extended = SimpleNamespace(**{field.name:getattr(value,field.name) for field in fields(value)},
        password=secret, seed=secret, private_key=secret)
    assert secret not in json.dumps(encode_config(extended))
    original = Path.open
    def reject_source(self, *a, **kw):
        if self.is_relative_to(value.input_path):
            raise AssertionError('journal read source contents')
        return original(self,*a,**kw)
    monkeypatch.setattr(Path,'open',reject_source)
    store=ScanJobStore(tmp_path/'jobs')
    job=store.begin(value)
    assert store.load(job.job_id).config == value


@pytest.mark.parametrize('operation', ['fsync','replace'])
def test_atomic_job_failure_preserves_previous_valid_record(tmp_path,monkeypatch,operation):
    import bfrs.reporting.atomic_output as atomic
    store=ScanJobStore(tmp_path/'jobs')
    job=store.begin(config(tmp_path,count=1))
    path=store.directory/f'{job.job_id}.json'
    before=path.read_bytes()
    def fail(*a,**kw):
        raise OSError(errno.ENOSPC,'synthetic metadata disk full')
    with monkeypatch.context() as patch:
        patch.setattr(atomic.os,operation,fail)
        with pytest.raises(OSError): store.set_state(job.job_id,'stopped')
    assert path.read_bytes()==before
    assert store.load(job.job_id).state=='running'


def test_process_exit_mid_journal_replace_keeps_original_record(tmp_path):
    store=ScanJobStore(tmp_path/'jobs')
    job=store.begin(config(tmp_path,count=1))
    code='''
import os,sys
from pathlib import Path
from bfrs.gui.scan_jobs import ScanJobStore
import bfrs.reporting.atomic_output as atomic
atomic.os.replace=lambda *a,**k: os._exit(31)
ScanJobStore(Path(sys.argv[1])).set_state(sys.argv[2],'stopped')
'''
    env=dict(os.environ,PYTHONPATH=str(Path(__file__).parents[1]/'src'))
    process=subprocess.run([sys.executable,'-c',code,str(store.directory),job.job_id],env=env,timeout=20)
    assert process.returncode==31
    assert store.load(job.job_id).state=='running'
    assert len(store.incomplete())==1
    assert not store.load_errors


def test_bad_or_future_job_is_reported_without_echoing_its_payload(tmp_path):
    store=ScanJobStore(tmp_path/'jobs')
    job=store.begin(config(tmp_path,count=1))
    path=store.directory/f'{job.job_id}.json'
    payload=json.loads(path.read_text(encoding='utf-8'))
    payload['config']['password']='DO_NOT_ECHO_THIS'
    path.write_text(json.dumps(payload),encoding='utf-8')
    assert not store.incomplete()
    assert store.load_errors and 'DO_NOT_ECHO_THIS' not in str(store.load_errors)


@pytest.fixture
def qtapp():
    pytest.importorskip('PySide6')
    os.environ.setdefault('QT_QPA_PLATFORM','offscreen')
    from PySide6.QtWidgets import QApplication
    app=QApplication.instance() or QApplication([])
    yield app


class Signal:
    def connect(self, target): pass


class FakeThread:
    def __init__(self,*a): self.started,self.finished=Signal(),Signal()
    def start(self): pass
    def quit(self): pass
    def deleteLater(self): pass


class FakeWorker:
    captured=None
    def __init__(self,value,controller):
        type(self).captured=value
        self.event,self.finished,self.failed=Signal(),Signal(),Signal()
    def moveToThread(self,*a): pass
    def run(self): pass
    def deleteLater(self): pass


def _windowed_worker(value,messages,stop_event):
    # Match PyInstaller console=False without building an installer.
    from bfrs.application.process_scan_runner import _worker_entry
    sys.stdout=sys.stderr=None
    _worker_entry(value,messages,stop_event)


def _result_then_crash_worker(value,messages,stop_event):
    from bfrs.application.scan_service import ScanRunResult
    messages.put(('result',ScanRunResult(0,value.output_path,'completed')))
    messages.close()
    messages.join_thread()
    os._exit(17)


def test_nonzero_process_exit_is_not_hidden_by_terminal_engine_result(tmp_path):
    from bfrs.application.process_scan_runner import ProcessScanError
    events=[]
    value=config(tmp_path,count=1)
    with pytest.raises(ProcessScanError,match='process exit code 17'):
        ProcessScanRunner(worker_entry=_result_then_crash_worker,event_sink=events.append).run(value)
    assert isinstance(events[-1],ScanFailedEvent)
    assert 'after terminal engine result 0' in events[-1].message


@pytest.mark.parametrize('compatible',[False,True])
def test_spawned_windowed_worker_without_stdio_preserves_result_and_diagnostic(tmp_path,compatible):
    value=config(tmp_path)
    stop36(value)
    resumed=replace(value,checkpoint=None,resume_checkpoint=value.checkpoint)
    if not compatible:
        resumed=replace(resumed,targets=frozenset({'electrum'}))
    events=[]
    result=ProcessScanRunner(worker_entry=_windowed_worker,event_sink=events.append).run(resumed)
    if compatible:
        assert result.completed and value.output_path.is_file()
    else:
        assert result.exit_code==3
        assert 'settings mismatch' in [e.message for e in events if isinstance(e,ScanFailedEvent)][-1]


def test_gui_restart_36_percent_missing_output_workers_and_real_process_resume(tmp_path,qtapp,monkeypatch):
    from bfrs.gui.settings import GuiSettingsStore,GuiPreferences
    import bfrs.gui.main_window as gui
    value=config(tmp_path)
    settings=GuiSettingsStore(tmp_path/'preferences/gui-settings.json')
    store=ScanJobStore(settings.path.parent/'scan-jobs')
    job=store.begin(value)  # Durable before the worker starts.
    stop36(value)
    protect_committed_rows(value.checkpoint)
    # Simulate loss/clearing of optional preferences and destruction of the GUI.
    settings.save(GuiPreferences(last_output=''))
    window=gui.MainWindow(settings_store=settings)
    window.saved_jobs_combo.setCurrentIndex(window.saved_jobs_combo.findData(job.job_id))
    window._load_saved_job()
    assert window.checkpoint_edit.text()==str(value.checkpoint)
    assert window._selected_targets()==value.targets
    assert not window.mnemonic_check.isChecked()
    window.output_edit.clear()
    window.workers_spin.setValue(4)
    window.file_workers_spin.setValue(2)
    monkeypatch.setattr(gui,'QThread',FakeThread)
    monkeypatch.setattr(gui,'ScanWorker',FakeWorker)
    window._start_scan()
    resumed=FakeWorker.captured
    assert resumed.output_path==value.output_path
    assert resumed.resume_checkpoint==value.checkpoint
    assert resumed.workers==4 and resumed.file_workers==2
    assert len(store.incomplete())==2
    try:
        result=ProcessScanRunner(event_sink=window._handle_event).run(resumed)
        assert result.completed
        report=json.loads(value.output_path.read_text(encoding='utf-8'))
        assert report['checkpoint']['resumed_files']==9
        assert report['files_scanned']==25
        assert len(report['target_findings'])==25
        assert len({row['file_path'] for row in report['target_findings']})==25
        baseline=replace(value,checkpoint=None,output_path=tmp_path/'baseline.json')
        assert ScanService().run(baseline).completed
        assert report['target_findings']==json.loads(baseline.output_path.read_text(encoding='utf-8'))['target_findings']
        assert not store.incomplete()
    finally:
        window._thread=None
        window._worker=None
        window.close()


def test_gui_cannot_start_if_request_journal_cannot_be_saved(tmp_path,qtapp,monkeypatch):
    from bfrs.gui.settings import GuiSettingsStore
    from bfrs.gui.main_window import MainWindow
    from PySide6.QtWidgets import QMessageBox
    value=config(tmp_path,count=1)
    window=MainWindow(settings_store=GuiSettingsStore(tmp_path/'prefs/settings.json'))
    window.source_edit.setText(str(value.input_path))
    window.output_edit.setText(str(value.output_path))
    def fail(*a,**kw): raise PermissionError('synthetic journal permission denied')
    monkeypatch.setattr(window._job_store,'begin',fail)
    seen=[]
    monkeypatch.setattr(QMessageBox,'warning',lambda *args: seen.append(args[-1]))
    window._start_scan()
    assert window._thread is None and seen
    assert 'synthetic journal permission denied' in seen[0]
    window.close()


def test_incompatible_resume_preserves_checkpoint_and_original_task_and_diagnostic(tmp_path):
    value=config(tmp_path)
    store=ScanJobStore(tmp_path/'jobs')
    job=store.begin(value)
    stop36(value)
    events=[]
    wrong=replace(job.for_resume(),targets=frozenset({'electrum'}),output_path=tmp_path/'changed-name.json')
    result=ProcessScanRunner(event_sink=events.append).run(wrong)
    assert result.exit_code==3
    failure=[e for e in events if isinstance(e,ScanFailedEvent)][-1]
    assert 'settings mismatch' in failure.message and 'targets' in failure.message
    assert 'BFRS scan exited with code 3' not in failure.message
    assert failure.message in explain_scan_error(failure.message)
    assert store.load(job.job_id).config==value
    with sqlite3.connect(value.checkpoint) as db:
        assert db.execute('SELECT count(*) FROM outcomes').fetchone()[0]==9
    assert not wrong.output_path.exists()


@pytest.mark.parametrize('failure_kind',['space','permission','race'])
def test_report_publication_failure_then_new_path_resume_without_replay(tmp_path,monkeypatch,failure_kind):
    import bfrs.reporting.atomic_output as atomic
    value=config(tmp_path)
    original=atomic.publish
    def fail(temporary,destination,*,overwrite=True):
        if destination==value.output_path:
            if failure_kind=='race':
                destination.write_bytes(b'existing user report remains unchanged')
            else:
                code=errno.ENOSPC if failure_kind=='space' else errno.EACCES
                raise OSError(code,'synthetic report write failure')
        return original(temporary,destination,overwrite=overwrite)
    events=[]
    with monkeypatch.context() as patch:
        patch.setattr(atomic,'publish',fail)
        result=ScanService(event_sink=events.append).run(value)
    assert result.exit_code==4
    assert 'report error:' in [e.message for e in events if isinstance(e,ScanFailedEvent)][-1]
    with sqlite3.connect(value.checkpoint) as db:
        assert db.execute("SELECT value FROM metadata WHERE key='state'").fetchone()[0]=='IN_PROGRESS'
        assert db.execute('SELECT count(*) FROM outcomes').fetchone()[0]==25
    protect_committed_rows(value.checkpoint)
    repaired=replace(value,checkpoint=None,resume_checkpoint=value.checkpoint,output_path=tmp_path/'fixed.json')
    assert ScanService().run(repaired).completed
    assert json.loads(repaired.output_path.read_text(encoding='utf-8'))['checkpoint']['resumed_files']==25
    if failure_kind=='race':
        assert value.output_path.read_bytes()==b'existing user report remains unchanged'


def test_existing_report_and_missing_source_fail_before_scanning(tmp_path):
    value=config(tmp_path,count=1)
    value.output_path.write_bytes(b'existing report')
    events=[]
    result=ScanService(event_sink=events.append).run(value)
    assert result.exit_code==4 and not value.checkpoint.exists()
    assert value.output_path.read_bytes()==b'existing report'
    value=replace(value,input_path=tmp_path/'unavailable/source.img',output_path=tmp_path/'new.json')
    result=ScanService(event_sink=events.append).run(value)
    assert result.exit_code==3
    assert 'source unavailable' in events[-1].message


def test_changed_source_location_is_refused_without_rewriting_checkpoint(tmp_path):
    value=config(tmp_path)
    stop36(value)
    moved=tmp_path/'moved'
    value.input_path.rename(moved)
    resumed=replace(value,checkpoint=None,resume_checkpoint=value.checkpoint,input_path=moved)
    events=[]
    assert ScanService(event_sink=events.append).run(resumed).exit_code==3
    assert 'source root mismatch' in events[-1].message
    assert not value.output_path.exists()


def test_image_checkpoint_geometry_workers_report_failure_and_repair(tmp_path,monkeypatch):
    from bfrs.core.chunk_reader import ChunkReader
    from tests.test_cli import valid_wif
    import bfrs.reporting.atomic_output as atomic
    step=1024**2-64*1024
    source=tmp_path/'synthetic.img'
    data=bytearray(25*step+64*1024)
    for i in range(25): data[i*step+100:i*step+100+len(valid_wif())]=valid_wif()
    source.write_bytes(data)
    value=ScanConfig(input_path=source,output_path=tmp_path/'image.json',
        source_type=SourceType.IMAGE,checkpoint=tmp_path/'image.sqlite',chunk_mib=1,
        targets=frozenset({'secrets'}),skip_mnemonic=True,protect_existing_report=True)
    store=ScanJobStore(tmp_path/'jobs')
    job=store.begin(value)
    controller=ScanController()
    def stop(event):
        if isinstance(event,ScanProgressEvent) and event.stage is None and event.scanned_bytes>=9*step:
            controller.request_stop()
    assert ScanService(controller=controller,event_sink=stop).run(value).exit_code==130
    assert store.load(job.job_id).config==value
    resumed=store.load(job.job_id).for_resume()
    events=[]
    assert ScanService(event_sink=events.append).run(replace(resumed,chunk_mib=2)).exit_code==3
    assert 'range/chunk configuration mismatch' in events[-1].message
    original=ChunkReader.iter_owned_chunks
    observed=[]
    def observe(self,*a,**kw):
        for start,end,chunk in original(self,*a,**kw):
            if chunk is not None: observed.append(start)
            yield start,end,chunk
    monkeypatch.setattr(ChunkReader,'iter_owned_chunks',observe)
    publish=atomic.publish
    def full(temporary,destination,*,overwrite=True):
        if destination==value.output_path: raise OSError(errno.ENOSPC,'synthetic report full')
        return publish(temporary,destination,overwrite=overwrite)
    with monkeypatch.context() as patch:
        patch.setattr(atomic,'publish',full)
        assert ScanService().run(replace(resumed,workers=4)).exit_code==4
    assert observed and min(observed)>=9*step
    observed.clear()
    # Unified checkpoints already allow completed ownership state to be reused;
    # report failure must not require replay or a checkpoint format change.
    fixed=replace(resumed,workers=2,output_path=tmp_path/'fixed-image.json')
    assert ScanService().run(fixed).completed
    assert not observed
    payload=json.loads(fixed.output_path.read_text(encoding='utf-8'))
    assert len(payload['target_findings'])==25
    assert [row['physical_start'] for row in payload['target_findings']]==[i*step+100 for i in range(25)]


def test_close_requests_cooperative_stop_before_destroying_qthread(tmp_path,qtapp):
    from PySide6.QtGui import QCloseEvent
    from bfrs.gui.settings import GuiSettingsStore
    from bfrs.gui.main_window import MainWindow
    window=MainWindow(settings_store=GuiSettingsStore(tmp_path/'prefs/settings.json'))
    window._thread=FakeThread()
    window._controller=ScanController()
    event=QCloseEvent()
    window.closeEvent(event)
    assert not event.isAccepted()
    assert window._controller.stop_requested and window._closing_requested
    window._cleanup_thread()
    assert window._thread is None


@pytest.mark.parametrize('message',[
    'report error: [Errno 28] No space left on device',
    'report error: [Errno 13] Permission denied',
    'folder checkpoint error: scanner settings mismatch: targets',
    'checkpoint source mismatch: source identity differs',
    'isolated scan worker exited unexpectedly (process exit code 7)',
    'BFRS scan exited with code 3',
])
def test_guidance_keeps_original_engine_reason(message):
    for language in ('pl','en'):
        assert explain_scan_error(message,language).startswith(message+'\n\n')


def test_gui_failure_result_never_clears_the_specific_engine_reason(tmp_path,qtapp):
    from bfrs.gui.main_window import MainWindow
    from bfrs.gui.settings import GuiSettingsStore
    from bfrs.application.scan_service import ScanRunResult
    window=MainWindow(settings_store=GuiSettingsStore(tmp_path/'prefs/settings.json'))
    reason='folder checkpoint error: scanner settings mismatch: targets'
    window._handle_event(ScanFailedEvent(reason,'ScanExitCode',True))
    window._scan_finished(ScanRunResult(3,tmp_path/'report.json','failed'))
    assert reason in window.status_label.text()
    window._last_failure_message=None
    window._scan_finished(ScanRunResult(3,tmp_path/'report.json','failed'))
    assert 'no detailed engine diagnostic' in window.status_label.text()
    window.close()


def test_missing_or_existing_report_is_form_error_not_generic_code3(tmp_path):
    from bfrs.gui.configuration import build_gui_scan_config
    kwargs=dict(input_path=str(tmp_path),output_path='',source_type='folder',
        targets=frozenset({'secrets'}),include_mnemonic=False,include_bitcoin_context=False,workers=1,file_workers=1)
    with pytest.raises(ValueError,match='raportu'):
        build_gui_scan_config(**kwargs)
    report=tmp_path/'existing.json'
    report.write_bytes(b'existing report')
    with pytest.raises(ValueError,match='już istnieje'):
        build_gui_scan_config(**dict(kwargs,output_path=str(report)))
    assert report.read_bytes()==b'existing report'


def test_engine_diagnostic_survives_unterminated_long_progress_line():
    import io
    from bfrs.application.scan_diagnostics import DiagnosticStderr
    seen=[]
    stream=DiagnosticStderr(io.StringIO(),seen.append)
    stream.write('\rFolder scan: '+('x'*20000))
    assert len(stream.pending)<=8192
    reason='folder checkpoint error: scanner settings mismatch: targets'
    stream.write(reason)
    stream.write('\n')
    assert seen==[reason]


def test_parser_error_reaches_service_instead_of_only_systemexit_code(tmp_path):
    value=config(tmp_path,count=1)
    value=replace(value,input_path=next(value.input_path.iterdir()),source_type=SourceType.FILE,
        checkpoint=None,file_workers=2)
    events=[]
    assert ScanService(event_sink=events.append).run(value).exit_code==2
    assert 'file-workers is only supported' in events[-1].message


def test_real_qthread_process_close_finishes_before_window_destruction(tmp_path,qtapp,monkeypatch):
    import time
    import faulthandler
    from PySide6.QtCore import QObject,Slot
    from bfrs.application.scan_events import ScanStartedEvent
    from bfrs.gui.main_window import MainWindow
    from bfrs.gui.settings import GuiSettingsStore
    value=config(tmp_path)
    window=MainWindow(settings_store=GuiSettingsStore(tmp_path/'prefs/settings.json'))
    window.source_edit.setText(str(value.input_path))
    window.output_edit.setText(str(value.output_path))
    window.checkpoint_edit.setText(str(value.checkpoint))
    original=window._handle_event
    requested=[]
    class Observer(QObject):
        @Slot(object)
        def events(self,event):
            original(event)
            if isinstance(event,ScanStartedEvent):
                window.close()
                requested.append(window._thread is not None and window._closing_requested)
    observer=Observer(window)
    monkeypatch.setattr(window,'_handle_event',observer.events)
    faulthandler.dump_traceback_later(15)
    window.show()
    window._start_scan()
    deadline=time.monotonic()+20
    while window._thread is not None and time.monotonic()<deadline:
        qtapp.processEvents()
        time.sleep(.01)
    assert requested==[True]
    assert window._thread is None
    qtapp.processEvents()
    faulthandler.cancel_dump_traceback_later()
    jobs=list(window._job_store.directory.glob('*.json'))
    assert jobs
    assert all(json.loads(path.read_text(encoding='utf-8'))['state'] in ('stopped','completed') for path in jobs)
