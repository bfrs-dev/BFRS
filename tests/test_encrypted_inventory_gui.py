"""Synthetic integration of the existing inventory engine, Qt and packaging."""
import builtins
import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import struct
import subprocess
import sys
import threading
import time

os.environ.setdefault('QT_QPA_PLATFORM','offscreen')
import pytest
pytest.importorskip('PySide6')
from PySide6.QtCore import QCoreApplication, QEvent, QThread, QTimer
from PySide6.QtWidgets import QApplication
from bfrs.application import document_inventory as engine
from bfrs.gui.inventory_panel import InventoryPanel
from bfrs.gui.main_window import MainWindow
from bfrs.gui.settings import GuiSettingsStore
from tests.test_container_inventory import zip_fixture, ole_fixture, rar3_header
from tests.test_seven_zip_inventory import archive, plain_header
from tests.test_ppt_inventory import records
from tests.test_pdf_inventory import classic_pdf


@pytest.fixture
def app():
    application = QApplication.instance() or QApplication([])
    yield application
    # pytest has no app.exec() loop to drain DeferredDelete on shutdown.
    # Release idle windows/threads while the application is still alive.
    for widget in application.topLevelWidgets():
        assert not any(thread.isRunning() for thread in widget.findChildren(QThread))
        widget.close()
        widget.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    application.processEvents()


def wait(app, predicate, timeout=20):
    deadline=time.monotonic()+timeout
    while not predicate() and time.monotonic()<deadline:
        app.processEvents()
        time.sleep(.002)
    assert predicate(), 'Background operation timed out'


def finish(app,panel):
    wait(app,lambda: not panel.busy)


def corpus(source):
    source.mkdir()
    zip_fixture(source/'żółty.zip',encrypted=True)
    (source/'archiwum.rar').write_bytes(b'Rar!\x1a\x07\x00'+rar3_header(0x73,0x80,b'\0'*6))
    (source/'archiwum.7z').write_bytes(archive(plain_header(b'\x06\xf1\x07\x01',b'\x00')))
    classic_pdf(source/'szyfr.pdf',b'/Encrypt 8 0 R')
    fib=bytearray(32); fib[:2]=b'\xec\xa5'; struct.pack_into('<H',fib,10,0x100)
    ole_fixture(source/'dokument.doc',{'WordDocument':fib})
    bof=struct.pack('<HH',0x0809,4)+b'\x00\x06\x05\x00'
    ole_fixture(source/'arkusz.xls',{'Workbook':bof+struct.pack('<HH',0x2f,6)+b'\0'*6+struct.pack('<HH',0x0a,0)})
    current,document=records(token=0xf3d1c4df,reference=2)
    ole_fixture(source/'slajdy.ppt',{'Current User':current,'PowerPoint Document':document})
    (source/'uszkodzony.pdf').write_bytes(b'%PDF-1.7\n')
    (source/'zwykły.rtf').write_bytes(br'{\rtf1 ordinary}')
    (source/'pusty.bin').touch()
    (source/'zwykły.txt').write_text('synthetic non-secret text',encoding='utf-8')


def test_same_synthetic_formats_cli_gui_filters_metadata_and_unicode(tmp_path,app):
    pytest.importorskip('olefile')
    source=tmp_path/'źródło'; corpus(source)
    panel=InventoryPanel()
    panel.source_edit.setText(str(source)); panel.output_edit.setText(str(tmp_path/'gui'))
    ticks=[]; timer=QTimer(); timer.timeout.connect(lambda: ticks.append(1)); timer.start(1)
    panel.start_inventory(); finish(app,panel); timer.stop()
    assert ticks and not panel.last_error and panel.last_result['complete']
    result=subprocess.run([sys.executable,'scripts/inventory_documents.py','--source',str(source),
        '--output',str(tmp_path/'cli')],cwd=Path(__file__).resolve().parents[1],capture_output=True)
    assert result.returncode==0,result.stderr
    assert (tmp_path/'gui/inventory.jsonl').read_bytes()==(tmp_path/'cli/inventory.jsonl').read_bytes()
    assert json.loads((tmp_path/'gui/summary.json').read_text(encoding='utf-8'))==json.loads(
        (tmp_path/'cli/summary.json').read_text(encoding='utf-8'))
    rows={row['path']:row for row in map(json.loads,(tmp_path/'gui/inventory.jsonl').read_text(encoding='utf-8').splitlines())}
    for name in ('żółty.zip','archiwum.rar','archiwum.7z','szyfr.pdf','dokument.doc','arkusz.xls','slajdy.ppt'):
        assert rows[name]['encryption']=='ENCRYPTED',(name,rows[name])
    assert rows['uszkodzony.pdf']['encryption']=='UNKNOWN'
    assert rows['zwykły.rtf']['encryption']=='NO_ENCRYPTION_INDICATOR'
    assert 'pusty.bin' not in rows  # Existing inventory scope: unsupported plain files cached, not reported.
    browser=panel.browser
    for index,state in enumerate(('ENCRYPTED','UNKNOWN','NO_ENCRYPTION_INDICATOR',None)):
        browser.state_combo.setCurrentIndex(index); finish(app,panel)
        assert browser.page.rows
        assert all(state is None or row['encryption']==state for row in browser.page.rows)
    browser.table.selectRow(0)
    assert str(source) in browser.table.item(0,5).text()
    assert 'bytes_read' in browser.details.toPlainText()
    browser.copy_selected(); assert str(source) in app.clipboard().text()
    browser.open_report(tmp_path/'cli/inventory.sqlite'); finish(app,panel)
    assert browser.database==tmp_path/'cli/inventory.sqlite'
    panel.close()


def test_stop_resume_large_tree_and_committed_units_no_duplicates(tmp_path,app,monkeypatch):
    source=tmp_path/'source'; source.mkdir()
    for index in range(1200):
        folder=source/str(index%7); folder.mkdir(exist_ok=True)
        (folder/f'żółty-{index}.rtf').write_bytes(br'{\rtf1 identical}')
    baseline=engine.inventory(source,tmp_path/'baseline')
    panel=InventoryPanel(); panel.source_edit.setText(str(source)); panel.output_edit.setText(str(tmp_path/'output'))
    original=engine.inspect_file; reached=threading.Event(); release=threading.Event(); calls=[]
    def inspect(path):
        calls.append(path)
        if len(calls)==9:
            reached.set(); assert release.wait(10)
        return original(path)
    monkeypatch.setattr(engine,'inspect_file',inspect)
    panel.start_inventory()
    wait(app,reached.is_set)
    panel.request_stop(); release.set(); finish(app,panel)
    assert panel.last_result['complete'] is False
    assert panel.last_result['run']['visited']==9
    assert panel.browser.page.counts['NO_ENCRYPTION_INDICATOR']==9
    first=set(calls); calls.clear()
    panel.source_edit.clear()
    panel.start_inventory(resume=True,database=tmp_path/'output/inventory.sqlite'); finish(app,panel)
    assert panel.source_edit.text()==str(source)
    assert panel.last_result['complete'] and panel.last_result['run']['reused']==9
    assert not first.intersection(calls)
    assert panel.last_result['encryption_counts']==baseline['encryption_counts']
    assert (tmp_path/'output/inventory.jsonl').read_bytes()==(tmp_path/'baseline/inventory.jsonl').read_bytes()
    assert panel.browser.table.rowCount()<=200
    panel.close()


@pytest.mark.parametrize('failure',['disk-full','permission','checkpoint'])
def test_write_and_checkpoint_errors_visible_and_repairable(tmp_path,app,monkeypatch,failure):
    source=tmp_path/'source'; source.mkdir(); (source/'a.rtf').write_bytes(br'{\rtf1 example}')
    output=tmp_path/'output'; panel=InventoryPanel()
    panel.source_edit.setText(str(source)); panel.output_edit.setText(str(output))
    if failure=='checkpoint':
        output.mkdir(); (output/'inventory.sqlite').write_bytes(b'not a SQLite checkpoint')
        panel.start_inventory(resume=True)
    else:
        def fail(*args,**kwargs):
            raise OSError(28,'synthetic disk full') if failure=='disk-full' else PermissionError(13,'synthetic permission denied')
        monkeypatch.setattr(engine,'write_json',fail)
        panel.start_inventory()
    finish(app,panel)
    assert panel.last_error and panel.last_error in panel.status.text()
    if failure!='checkpoint':
        assert panel.browser.page is not None
        monkeypatch.undo()
        panel.start_inventory(resume=True); finish(app,panel)
        assert panel.last_result['complete'] and panel.last_result['run']['reused']==1
    panel.close()


def test_existing_results_and_incompatible_resume_are_preserved(tmp_path,app):
    source=tmp_path/'source'; source.mkdir(); (source/'a.rtf').write_bytes(br'{\rtf1 example}')
    output=tmp_path/'output'; engine.inventory(source,output)
    original={name:(output/name).read_bytes() for name in ('inventory.jsonl','summary.json','inventory.sqlite')}
    panel=InventoryPanel(); panel.source_edit.setText(str(source)); panel.output_edit.setText(str(output))
    panel.start_inventory(); finish(app,panel)
    assert panel.last_error
    other=tmp_path/'other'; other.mkdir(); panel.source_edit.setText(str(other))
    panel.start_inventory(resume=True); finish(app,panel)
    assert 'Checkpoint' in panel.last_error
    for name,content in original.items():
        assert (output/name).read_bytes()==content
    panel.close()


def test_output_lock_rejects_concurrent_resume_without_modifying_results(tmp_path):
    source=tmp_path/'source'; source.mkdir(); output=tmp_path/'output'
    engine.inventory(source,output)
    before=(output/'inventory.sqlite').read_bytes()
    with engine._output_lock(output):
        with pytest.raises(ValueError,match='already in use'):
            engine.inventory(source,output,resume=True)
    assert (output/'inventory.sqlite').read_bytes()==before
    assert engine.inventory(source,output,resume=True)['complete']


def test_stop_while_walking_empty_directories(tmp_path):
    source=tmp_path/'source'; source.mkdir()
    for index in range(200): (source/str(index)).mkdir()
    calls=[]
    def stop(): calls.append(1); return len(calls)>12
    result=engine.inventory(source,tmp_path/'output',should_stop=stop)
    assert result['complete'] is False and len(calls)<25


def test_missing_optional_ole_is_unknown_and_gui_warns(tmp_path,app,monkeypatch):
    path=ole_fixture(tmp_path/'a.doc',{'WordDocument':b'\0'*32})
    original=builtins.__import__
    def missing(name,*args,**kwargs):
        if name=='olefile': raise ImportError('synthetic missing optional dependency')
        return original(name,*args,**kwargs)
    monkeypatch.setattr(builtins,'__import__',missing)
    row=engine.inspect_file(path)
    assert row['encryption']=='UNKNOWN' and row['reason']=='INSTALL_INVENTORY_EXTRA_FOR_OLE'
    find=importlib.util.find_spec
    monkeypatch.setattr(importlib.util,'find_spec',lambda name: None if name=='olefile' else find(name))
    panel=InventoryPanel(language='en')
    assert 'olefile is missing' in panel.dependency_note.text()
    panel.close()


def test_efs_folder_and_plain_child_keep_distinct_meaning_in_gui(tmp_path,app,monkeypatch):
    from tests.test_inventory_efs import windows_tree
    source=tmp_path/'źródło'; source.mkdir()
    (source/'zwykły.rtf').write_bytes(br'{\rtf1 ordinary}')
    windows_tree(monkeypatch,{source:0x4000})
    panel=InventoryPanel(); panel.source_edit.setText(str(source)); panel.output_edit.setText(str(tmp_path/'output'))
    panel.start_inventory(); finish(app,panel)
    assert panel.last_result['efs_counts']=={'files':0,'directories':1}
    assert panel.last_result['encryption_counts']['NO_ENCRYPTION_INDICATOR']==1
    panel.browser.table.selectRow(0)
    assert 'Nie potwierdza szyfrowania wszystkich' in panel.browser.details.toPlainText()
    panel.close()


def test_reparse_directory_not_traversed_and_linked_output_refused(tmp_path,monkeypatch):
    from tests.test_inventory_efs import windows_tree
    source=tmp_path/'source'; source.mkdir()
    linked=source/'junction'; linked.mkdir(); (linked/'hidden.rtf').write_bytes(br'{\rtf1 hidden}')
    windows_tree(monkeypatch,{linked:0x400})
    monkeypatch.setattr(engine,'inspect_file',lambda *args: pytest.fail('Must not inspect through a reparse point'))
    result=engine.inventory(source,tmp_path/'output')
    assert result['run']['inspected']==0 and result['run']['visited']==1
    row=json.loads((tmp_path/'output/inventory.jsonl').read_text(encoding='utf-8'))
    assert row['reason']=='LINK_OR_REPARSE_POINT_SKIPPED' and row['encryption']=='UNKNOWN'
    with pytest.raises(ValueError,match='reparse'):
        engine.inventory(linked,tmp_path/'other')


def test_source_read_error_is_unknown_with_reason_and_visible_counter(tmp_path,app,monkeypatch):
    source=tmp_path/'source'; source.mkdir(); (source/'denied.doc').write_bytes(b'synthetic')
    def denied(path): raise PermissionError('synthetic denied source')
    monkeypatch.setattr(engine,'inspect_file',denied)
    panel=InventoryPanel(); panel.source_edit.setText(str(source)); panel.output_edit.setText(str(tmp_path/'output'))
    panel.start_inventory(); finish(app,panel)
    assert not panel.last_error and panel.last_result['run']['errors_or_skips']==1
    panel.browser.state_combo.setCurrentIndex(1); finish(app,panel)
    assert panel.browser.page.rows[0]['reason']=='PermissionError'
    panel.close()


def test_main_window_third_tab_languages_and_safe_close(tmp_path,app,monkeypatch):
    window=MainWindow(settings_store=GuiSettingsStore(tmp_path/'preferences.json'))
    assert window.tabs.count()==4 and window.tabs.tabText(2)=='Zaszyfrowane pliki i foldery'
    assert window.tabs.tabText(3)=='ZIP w obrazie'
    window._language='en'; window._retranslate_ui()
    assert window.tabs.tabText(2)=='Encrypted files and folders'
    assert window.tabs.tabText(3)=='ZIP in image'
    assert window.inventory_panel.browser.state_combo.itemText(1)=='Unknown'
    source=tmp_path/'source'; source.mkdir(); (source/'a.rtf').write_bytes(br'{\rtf1 example}')
    gate=threading.Event(); entered=threading.Event(); original=engine.inspect_file
    def inspect(path): entered.set(); assert gate.wait(10); return original(path)
    monkeypatch.setattr(engine,'inspect_file',inspect)
    panel=window.inventory_panel; panel.source_edit.setText(str(source)); panel.output_edit.setText(str(tmp_path/'output'))
    window.show(); panel.start_inventory(); wait(app,entered.is_set)
    window.close()
    assert window._closing_requested and window.isVisible()
    gate.set(); finish(app,panel); wait(app,lambda: not window.isVisible())


def test_windowed_no_stdio_smoke_from_sources(tmp_path):
    result=subprocess.run([sys.executable,'-c',
        'import sys; sys.stdout=sys.stderr=None; from bfrs.gui.inventory_smoke import run_smoke; raise SystemExit(run_smoke(sys.argv[1]))',
        str(tmp_path/'smoke')],env={**os.environ,'PYTHONPATH':str(Path(__file__).resolve().parents[1]/'src')},timeout=90)
    outcome=json.loads((tmp_path/'smoke/smoke-result.json').read_text(encoding='utf-8'))
    assert result.returncode==0,json.dumps(outcome,ensure_ascii=False,indent=2)
    assert outcome['no_console'] and outcome['cli_gui_equal'] and outcome['resume']
    assert outcome['tabs']==4
    assert outcome['raw_zip_scan'] and outcome['raw_zip_resume'] and outcome['raw_zip_cli_gui_equal']


def test_build_contract_includes_frozen_verification_and_recursive_installer():
    root=Path(__file__).resolve().parents[1]
    script=(root/'scripts/build_windows.ps1').read_text(encoding='utf-8')
    assert '.[dev,gui,package,inventory]' in script
    assert script.index(r'scripts\verify_frozen_inventory.py') < script.index('if ($Installer)')
    spec=(root/'packaging/bfrs_gui.spec').read_text(encoding='utf-8')
    assert 'console=False' in spec and 'bfrs.application.document_inventory' in spec and '"olefile"' in spec
    assert 'recursesubdirs createallsubdirs' in (root/'packaging/bfrs.iss').read_text(encoding='utf-8')


@pytest.mark.skipif(not os.environ.get('BFRS_FROZEN_EXE'),reason='Set BFRS_FROZEN_EXE to run the actual packaged GUI')
def test_actual_frozen_inventory_without_source_imports(tmp_path):
    script=Path(__file__).resolve().parents[1]/'scripts/verify_frozen_inventory.py'
    result=subprocess.run([sys.executable,str(script),'--exe',os.environ['BFRS_FROZEN_EXE'],'--work',str(tmp_path)],
                          capture_output=True,timeout=120)
    assert result.returncode==0,result.stderr.decode(errors='replace')
    outcome=json.loads((tmp_path/'smoke/smoke-result.json').read_text(encoding='utf-8'))
    assert len(outcome['bundled_modules'])>=12
