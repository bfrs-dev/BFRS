# Windows EFS w surowym obrazie NTFS

W zakładce **ZIP / EFS w obrazie** wybierz **Windows EFS (NTFS)**,
wskaż obraz oraz nowy folder wyników i uruchom skan. Ten tryb analizuje
zachowane rekordy NTFS używanego przez Windows XP, Vista i 8/8.1; nie wymaga
uruchomienia starego Windows, montowania partycji ani certyfikatu EFS.
Nie rozpoznaje wersji systemu Windows na podstawie rekordu.

Obraz otwierany jest wyłącznie do odczytu. Skaner szuka sygnatur `FILE` w całym
pliku, również poza aktywną MFT. Sprawdza nagłówek rekordu, poprawki USA,
granice atrybutów, kodowanie nazw i strukturę list przebiegów. Nie podąża
za znalezionymi listami przebiegów i nie zapisuje danych, kluczy ani
certyfikatów z obrazu w raporcie.

## Interpretacja wyników

| Wynik | Znaczenie |
| --- | --- |
| Domyślne szyfrowanie folderu | Bit `0x4000` w `$STANDARD_INFORMATION` folderu. Nie dowodzi szyfrowania wszystkich dzieci. |
| `$EFS` i znacznik szyfrowania | Nagłówek `:$EFS:$LOGGED_UTILITY_STREAM` oraz znacznik w standardowych metadanych lub `$DATA`. Zawartość kryptograficzna strumienia nie jest walidowana. |
| Znacznik szyfrowania | Znacznik w standardowych metadanych lub `$DATA`, bez nagłówka `$EFS` w tym rekordzie. |
| Tylko nagłówek strumienia `$EFS` | Ślad do weryfikacji bez potwierdzenia znacznikiem. |
| Tylko kopia znacznika w nazwie | Słabszy ślad w `$FILE_NAME`; kopia atrybutów może być nieaktualna. |

Nazwa sugerująca portfel jest wskazówką do ustalenia kolejności analizy,
nie potwierdzeniem zawartości. Filtr nazw w GUI jest opcjonalny; domyślnie
pokazujemy wszystkie ślady EFS, także foldery o zwykłych nazwach.

Raport zawiera fizyczny offset rekordu, jego numer i sekwencję, zachowane nazwy,
odwołania do rodziców oraz podstawy klasyfikacji. Nie składa pełnych ścieżek
ani nie łączy rozszerzeń z rekordami bazowymi. Nie utożsamia numerów rekordów
z różnych partycji. Flaga zajętości opisuje znaleziony rekord, a nie potwierdzony
obecny stan pliku. Kopie MFT i stare rekordy mogą się powtarzać.

## Raport i wznowienie

- `efs_scan.sqlite`: trwały checkpoint i stronicowane wyniki GUI.
- `efs_hits.jsonl`: wszystkie znalezione rekordy z przesłankami EFS.
- `efs_wallet_names.jsonl`: ich podzbiór z nazwami sugerującymi portfel.
- `summary.json`: postęp, liczniki dowodów, przyczyna zatrzymania i ograniczenia.

Przycisk zatrzymania zapisuje postęp. Wznawiaj z tym samym obrazem, folderem
wyników i trybem EFS. Kontrolujemy ścieżkę, rozmiar, czasy, tożsamość pliku
i skróty trzech próbek. Nie jest to pełny hash obrazu. ZIP i EFS mają różne
formaty checkpointów. Zmiana trybu wyłącza zaznaczenie wznowienia.
Otwarcie pliku `efs_scan.sqlite` automatycznie wybiera EFS.

CLI z katalogu projektu:

```powershell
py .\scripts\inventory_efs_image.py --source "D:\obrazy\dysk.img" --output "C:\BFRS-EFS-01"
py .\scripts\inventory_efs_image.py --source "D:\obrazy\dysk.img" --output "C:\BFRS-EFS-01" --resume
```

Domyślny blok to 8 MiB, limit jednego uruchomienia to milion sygnatur `FILE`.
Po limicie można wznowić od pierwszej nieprzetworzonej sygnatury.
Checkpoint i wyniki bloku są zatwierdzane razem; baza jest jawnie zamykana.
Pamięć zależy od rozmiaru bloku, nie obrazu. Dodatkowy odczyt na sygnaturę
jest ograniczony do 48 bajtów nagłówka i maksymalnie 64 KiB rekordu.
Rekordy bez śladów EFS nie są przechowywane; licznik odrzuconych sygnatur
obejmuje zarówno je, jak i rekordy niepoprawne lub nieobsługiwane.

## Ograniczenia i weryfikacja

Obsługiwane są ciągłe rekordy `FILE` o rozmiarach będących potęgami dwóch
od 512 B do 64 KiB, z nagłówkiem stosowanym w NTFS 3.1 i poprawkami USA
co 512, 1024, 2048 lub 4096 B. Nie składamy fragmentów uszkodzonego rekordu,
nie analizujemy samodzielnych wpisów INDX ani kopii bez poprawnego USA.
Zniszczonych/nadpisanych metadanych nie da się w ten sposób wykryć.
Pełny przebieg i zero trafień **nie wykluczają wcześniejszego EFS**.

Wejście to surowe bajty obrazu (`.img`, `.dd`, `.bin` itp.). Nie dekodujemy
kontenerów E01/dynamicznych VHD/VHDX ani zaszyfrowanej partycji BitLocker.
Ten tryb nie wykrywa archiwów RAR/7z ani zabezpieczeń innych programów.

Testy używają syntetycznych metadanych, także uszkodzonych, nie gotowych
obrazów zaszyfrowanych na rzeczywistych instalacjach każdego z trzech systemów.
Weryfikator instalatora sprawdza skan EFS w GUI, zgodność z CLI, wznowienie
i obecność modułu wewnątrz EXE. Wykrycie metadanych nie jest odszyfrowaniem.

## Źródła formatu

- Microsoft: [File streams](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams)
- Microsoft: [Handling encrypted files and directories](https://learn.microsoft.com/en-us/windows/win32/fileio/handling-encrypted-files-and-directories)
- Microsoft: [Attribute record header](https://learn.microsoft.com/en-us/windows/win32/devnotes/attribute-record-header)
- Microsoft: [File record segment header](https://learn.microsoft.com/en-us/windows/win32/devnotes/file-record-segment-header)
- Linux NTFS3: [NTFS structures](https://github.com/torvalds/linux/blob/master/fs/ntfs3/ntfs.h)
