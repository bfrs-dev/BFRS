# Historyczne formaty `wallet.dat` Bitcoin 2009–2014

## 1. Cel, zakres i poziom pewności

Ten dokument jest specyfikacją wejściową do przyszłego odzyskiwania rekordów legacy Bitcoin/Bitcoin-Qt/Bitcoin Core w BFRS 2.0. Obejmuje format logicznych kluczy i wartości Berkeley DB, nie układ stron Berkeley DB. Kod produkcyjny nie jest tu projektowany ani implementowany.

Wnioski pochodzą przede wszystkim z oficjalnego repozytorium `bitcoin/bitcoin`: historycznych tagów, `git log -S/-G`, `git show` i kodu serializerów. Obecny kod jest użyty wyłącznie do sprawdzenia zachowanej kompatybilności. Statusy znaczą:

- **CONFIRMED** — bezpośrednio potwierdzone kodem zapisu/odczytu albo historią zmiany;
- **PARTIALLY CONFIRMED** — potwierdzony loader lub struktura, ale nie potwierdzono np. normalnego writera;
- **UNKNOWN** — brak dostatecznego dowodu; nie wolno zamieniać na domysł.

„First confirmed” oznacza najwcześniejszy stan znaleziony w oficjalnej historii, a nie dowód, że nie istniał żaden wcześniejszy build poza tą historią. Daty są datami commitów. Dla tagów anotowanych commit wskazany przez tag może mieć inną datę niż publikacja wydania.

## 2. Audytowane punkty odniesienia

| Okres | Źródło odniesienia | Commit / data | Najważniejsze pliki |
|---|---|---|---|
| 2009, 0.1.x | [`v0.1.5`](https://github.com/bitcoin/bitcoin/tree/v0.1.5) | `8dca7864f793072701f810e4c5ea12a6e1087085`, 2009-09-16 | `db.cpp`, `db.h`, `key.h`, `serialize.h` |
| 2010, późny pre-encryption | [`v0.3.19`](https://github.com/bitcoin/bitcoin/tree/v0.3.19) | `fc73ad644f0b87b91f49b7f6f6b2348f78bdbbf4`, 2010-12-13 | `db.cpp`, `db.h`, `main.h`, `serialize.h` |
| 2011, pre-0.4 | [`v0.3.24`](https://github.com/bitcoin/bitcoin/tree/v0.3.24) | `f08736405e98d0f16ec294606dda782043d5ab3d`, 2011-07-08 | `src/db.cpp`, `src/db.h`, `src/wallet.h`, `src/serialize.h` |
| 2011, encryption | [`v0.4.0`](https://github.com/bitcoin/bitcoin/tree/v0.4.0) | `c7eb151ad0ed441d6fd598551059a9bbfb09e99e`, 2011-09-22 | `src/db.cpp`, `src/db.h`, `src/crypter.*`, `src/keystore.*`, `src/wallet.*` |
| 2012 | [`v0.6.3`](https://github.com/bitcoin/bitcoin/tree/v0.6.3) | `6e0c5e3778b83f128f6f14c311d5728392053581`, 2012-06-19 | `src/walletdb.*`, `src/wallet.*`, `src/key.*`, `src/serialize.h` |
| 2013, 0.8.x | [`v0.8.6`](https://github.com/bitcoin/bitcoin/tree/v0.8.6) | `03a7d673876dc8fbae876290b455c02b0cac80bd`, 2013-11-27 | `src/walletdb.*`, `src/wallet.*`, `src/key.*`, `src/serialize.h` |
| 2014 | [`v0.9.3`](https://github.com/bitcoin/bitcoin/tree/v0.9.3) | `40d20412ff173e8eea2f456fd749663c8cabda18`, 2014-09-22 | `src/walletdb.*`, `src/wallet.*`, `src/key.*`, `src/serialize.h` |
| current, tylko kompatybilność | `master` w czasie audytu | `128456b62d5e38abea031f97f823d5b28aef9357`, 2026-08-08 | `src/wallet/walletdb.cpp`, `src/wallet/migrate.cpp` |

Najwcześniejszym audytowanym przodkiem zawierającym obsługę portfela jest oficjalny [`e071a3f6…`](https://github.com/bitcoin/bitcoin/commit/e071a3f6c06f41068ad17134189a4ac3073ef76b) z 2009-08-30 („First commit”).

## 3. Notacja i wspólne reguły serializacji

W dalszej części:

- `CS(n)` — CompactSize liczby `n`;
- `STR(x)` — `CS(len(x)) || bytes(x)`;
- `VEC(x)` — `CS(len(x)) || x` dla `vector<unsigned char>`;
- `PUB` — surowy SEC public key opakowany jako `VEC(PUB)`/`CPubKey`;
- `PRIV_DER` — OpenSSL DER `ECPrivateKey`, opakowany jako `VEC(PRIV_DER)` (`CPrivKey`);
- `u32`, `i32`, `u64`, `i64` — historyczne pola stałej szerokości. Najstarszy `serialize.h` używał surowego `WRITEDATA` pamięci hosta, bez jawnej normalizacji endian; dla dominującego profilu x86/x64 walleta są little-endian. BFRS nie powinien ogłaszać big-endian walleta niemożliwym bez osobnego audytu historycznych buildów;
- `||` — bezpośrednia konkatenacja, bez dodatkowej długości dla `pair`/`tuple`.

### 3.1. `std::string` i `vector<unsigned char>`

[`serialize.h` z v0.1.5](https://github.com/bitcoin/bitcoin/blob/v0.1.5/serialize.h) oraz kolejne audytowane wersje zapisują `std::string` jako CompactSize długości i surowe bajty. Fundamentalny `vector<unsigned char>` ma dokładnie tę samą warstwę długości i surowe bajty. Nie ma terminatora NUL.

CompactSize ma progi `0..252` w jednym bajcie, `0xfd + u16`, `0xfe + u32`, `0xff + u64`. Writer od 2009 tworzył formę minimalną. Reader 2009–0.8.x akceptował także nieminimalne reprezentacje; kontrolę „non-canonical ReadCompactSize()” wprowadzono w commicie [`8dc206a1…`](https://github.com/bitcoin/bitcoin/commit/8dc206a1e2715be83912e039465a049b708b94c1) z 2013-08-07, pierwszym potwierdzonym w audytowanych wydaniach od `v0.9.0`.

Wniosek dla forensics: forma kanoniczna jest mocnym dowodem writera, ale nieminimalnego CompactSize nie wolno globalnie odrzucać jako „historycznie niemożliwego”; stary loader mógł go przyjąć. Powinien obniżać pewność i być oznaczony jako `legacy-reader-accepted`, nie automatycznie niszczyć kandydata.

### 3.2. Dokładne prefiksy nazw typów

Nazwy typów same są serializowanymi stringami, nie dowolnym ASCII znalezionym w stronie DB:

| Typ | Początek logicznego klucza DB (hex + ASCII) |
|---|---|
| `key` | `03 6b 65 79` |
| `wkey` | `04 77 6b 65 79` |
| `defaultkey` | `0a 64 65 66 61 75 6c 74 6b 65 79` |
| `ckey` | `04 63 6b 65 79` |
| `mkey` | `04 6d 6b 65 79` |
| `keymeta` | `07 6b 65 79 6d 65 74 61` |
| `pool` | `04 70 6f 6f 6c` |
| `version` | `07 76 65 72 73 69 6f 6e` |
| `minversion` | `0a 6d 69 6e 76 65 72 73 69 6f 6e` |
| `name` / `tx` / `acc` | odpowiednio `04...`, `02...`, `03...` |
| `acentry` / `cscript` / `purpose` | `07...` |
| `orderposnext` | `0c 6f 72 64 65 72 70 6f 73 6e 65 78 74` |

Decoder musi po nazwie sparsować właściwy suffix i wymagać poprawnej granicy rekordu. Sam substring `key`, `ckey` albo `mkey` nie jest dowodem walleta.

### 3.3. Public key

W 2009 `CKey::GetPubKey()` używał OpenSSL `i2o_ECPublicKey`; standardowym wynikiem był nieskompresowany SEC key: 65 surowych bajtów `04 || X(32) || Y(32)`, zapisany jako `41 || PUB65`. Obsługę compressed pubkeys dodano w [`11529c6e…`](https://github.com/bitcoin/bitcoin/commit/11529c6e4f7288d8a64c488a726ee3821c7adefe) z 2011-11-21, a wymaganie feature level 0.6.0 w [`38067c18…`](https://github.com/bitcoin/bitcoin/commit/38067c18f8b54c7121643fa3291ffe81b6eefef1) z 2012-02-18. Pierwszym potwierdzonym audytowanym wydaniem z tą obsługą jest `v0.6.0`.

Compressed SEC key ma 33 surowe bajty `02/03 || X(32)` i framing `21 || PUB33`. Walidacja musi sprawdzić jednocześnie CompactSize, dokładną konsumpcję, prefiks SEC i punkt na secp256k1. Same długości 33/65 nie wystarczą.

### 3.4. Plaintext private key

`CPrivKey` jest `vector<unsigned char, secure_allocator<...>>`. W [`key.h` v0.1.5](https://github.com/bitcoin/bitcoin/blob/v0.1.5/key.h) `GetPrivKey()` wywołuje `i2d_ECPrivateKey`, a `SetPrivKey()` — `d2i_ECPrivateKey`. Zatem wartość nie jest surowym 32-bajtowym sekretem: jest `VEC(OpenSSL DER ECPrivateKey)`.

Komentarz w [`src/key.h` v0.6.3](https://github.com/bitcoin/bitcoin/blob/v0.6.3/src/key.h) podaje 279 B dla kompletnej serializacji secp256k1 z parametrami i 65-bajtowym pubkey. Kod jednak oblicza długość dynamicznie przez `i2d_ECPrivateKey`; 279 jest potwierdzoną typową postacią historyczną, nie bezpiecznym globalnym `len == 279`. Validator powinien parsować DER, wymagać secp256k1, prawidłowego skalara i zgodności wyprowadzonego public key z kluczem DB.

## 4. Rekordy krytyczne

### 4.1. `key`

**Pierwsze potwierdzenie:** [`e071a3f6…`](https://github.com/bitcoin/bitcoin/commit/e071a3f6c06f41068ad17134189a4ac3073ef76b), 2009-08-30; writer `CWalletDB::WriteKey`, loader `CWalletDB::LoadWallet`/później `ReadKeyValue` w `db.h/db.cpp`. Obecny w `v0.1.5`.

**Berkeley key:**

```text
STR("key") || VEC(PUB)
03 6b 65 79 || 41 || SEC65                    # najstarsza typowa postać
03 6b 65 79 || 21 || SEC33                    # po compressed pubkeys
```

**Berkeley value, wariant K1 (2009–2013 i nadal czytany):**

```text
VEC(PRIV_DER)
```

**Berkeley value, wariant K2 (nowy writer od zmiany hash, wydania od 0.9.0):**

```text
VEC(PRIV_DER) || uint256(Hash(PUB_raw || PRIV_DER_raw))
```

Hash dodano w [`6e51b3bd…`](https://github.com/bitcoin/bitcoin/commit/6e51b3bddf782f53527cf968445b298ebdec9bbc) z 2013-08-28. Jest to 32-bajtowy serializowany `uint256` po DER, a hash obejmuje surowy SEC pubkey i surowy DER bez ich prefiksów CompactSize. [`walletdb.cpp` v0.9.3](https://github.com/bitcoin/bitcoin/blob/v0.9.3/src/walletdb.cpp) próbuje doczytać hash; EOF oznacza stary wariant. Gdy hash istnieje, porównuje go; gdy nie istnieje, odtwarza public key z DER i porównuje kryptograficznie.

**Materiał prywatny:** tak, plaintext. **Priorytet:** CRITICAL.

### 4.2. `wkey`

**Pierwsze potwierdzenie:** [`53d50807…`](https://github.com/bitcoin/bitcoin/commit/53d508072b02d522371bde148dcc3e925f472be7), 2010-02-03; `db.cpp::LoadWallet` oraz `main.h::CWalletKey`; pierwszy potwierdzony tag `v0.2.2`.

Komentarz klasy mówi: „Private key that includes an expiration date in case it never gets used.” To potwierdza intencję struktury. Audyt literalnego `"wkey"` w tagach `v0.2.2`–`v0.9.3` oraz `v0.18.1` znalazł loader i późniejsze kasowanie rekordu podczas szyfrowania, ale nie znalazł normalnego writera `wkey`. Dlatego obsługa historycznego formatu jest CONFIRMED, natomiast jego normalna produkcja i moment zaprzestania zapisu są UNKNOWN.

**Berkeley key:**

```text
STR("wkey") || VEC(PUB)
```

**Berkeley value W1, od 2010-02-03 do przed 0.2.6:**

```text
i32 object/stream version
|| VEC(PRIV_DER)
|| i64 nTimeCreated
|| i64 nTimeExpires
```

**Berkeley value W2, od [`cb420a1d…`](https://github.com/bitcoin/bitcoin/commit/cb420a1dfc23d3c11c5281ed8f7ae003c2f61594), 2010-02-23 (`v0.2.6`):**

```text
i32 object/stream version
|| VEC(PRIV_DER)
|| i64 nTimeCreated
|| i64 nTimeExpires
|| STR(strComment)
```

Późniejsze loadery do `v0.18.1` nadal rozpakowywały `CWalletKey` i pobierały `vchPrivKey`. Obecny `master` jawnie odrzuca `wkey` i sugeruje użycie wersji 0.18 do migracji; jest to dowód, że nowy parser BFRS nie może bazować wyłącznie na obecnym loaderze.

**Materiał prywatny:** tak, plaintext DER. **Priorytet:** CRITICAL.

### 4.3. `defaultkey`

**Pierwsze potwierdzenie:** [`e071a3f6…`](https://github.com/bitcoin/bitcoin/commit/e071a3f6c06f41068ad17134189a4ac3073ef76b), 2009-08-30; `CWalletDB::WriteDefaultKey` i loader. Obecny w `v0.1.5`, zapisywany jeszcze w `v0.9.3`.

**Berkeley key:** dokładnie `STR("defaultkey")`; brak trailing fields.

**Berkeley value:** `VEC(PUB)`/`CPubKey`.

Nie zawiera private key. Jest niezależnym, mocnym sygnałem starego walleta, jeżeli framing i SEC pubkey są prawidłowe. Nie wolno wymagać go globalnie: carving może być częściowy, a obecny kod zachowuje go już tylko jako legacy record i sprawdza poprawność, nie używa jako aktywnego klucza domyślnego.

**Priorytet:** SUPPORTING.

### 4.4. Moment wprowadzenia wallet encryption

Wallet encryption dodano w jednym potwierdzonym commicie [`4e87d341…`](https://github.com/bitcoin/bitcoin/commit/4e87d341f75f13bbd7d108c31c03886fbc4df56f), 2011-07-08 15:47:35 +02:00, „Add wallet privkey encryption”; pierwszy stabilny audytowany tag z tą funkcją to `v0.4.0`.

Różnica przed/po:

| Element | Przed (`v0.3.24`) | Po (`v0.4.0`) |
|---|---|---|
| `WriteKey` | zapisuje `key -> VEC(PRIV_DER)` | nadal obsługuje plaintext `key` |
| `WriteCryptedKey` | brak | zapisuje `ckey`, następnie kasuje odpowiadające `key` i `wkey` |
| `WriteMasterKey` | brak | zapisuje `mkey` z `CMasterKey` |
| loader | `key`/`wkey` | dodaje gałęzie `ckey` i `mkey`, oznacza wallet jako encrypted |
| private material | DER EC private key | `ckey` zawiera AES-256-CBC ciphertext 32-bajtowego `CSecret`; passphrase chroni master key w `mkey` |

`minversion` wprowadził osobny commit [`7ec55267…`](https://github.com/bitcoin/bitcoin/commit/7ec552676c66488fe00fb503d02ec4a389a715b7) z 2011-07-05. Jest obecny w `v0.4.0`, ale nie jest częścią samego formatu `ckey`/`mkey`.

### 4.5. `ckey`

**Berkeley key:**

```text
STR("ckey") || VEC(PUB)
```

**Berkeley value:**

```text
VEC(vchCryptedSecret)
```

`vchCryptedSecret` jest wynikiem AES-256-CBC z paddingiem OpenSSL nad dokładnie 32-bajtowym `CSecret`; IV pochodzi z `Hash(pubkey)`. Dla poprawnie utworzonego rekordu kodu 0.4 daje to typowo i oczekiwanie formatowe 48 B ciphertext, zapisane jako `30 || 48 bytes`. Wstępny validator powinien jednak najpierw sprawdzać niepustą długość będącą wielokrotnością bloku AES, a profil historyczny oznaczać `len == 48` jako oczekiwany; pełne potwierdzenie wymaga odszyfrowania i zgodności z public key.

Kształt rekordu pozostaje stabilny w audytowanych `v0.4.0`, `v0.6.3`, `v0.8.6`, `v0.9.3`. Zmienna postać `PUB` dopuszcza 65 B, a po feature 0.6 także 33 B. Od wprowadzenia `keymeta` writer `ckey` zapisuje dodatkowy, osobny rekord `keymeta`; nie zmienia to value `ckey`.

**Materiał prywatny:** tak, zaszyfrowany sekret. **Priorytet:** CRITICAL.

### 4.6. `mkey`

**Berkeley key:**

```text
STR("mkey") || u32 nID
```

`nID` jest 4-bajtowym `unsigned int`, nie CompactSize.

**Berkeley value (`CMasterKey`) w kolejności potwierdzonej przez [`src/crypter.h` v0.4.0](https://github.com/bitcoin/bitcoin/blob/v0.4.0/src/crypter.h):**

```text
VEC(vchCryptedKey)
|| VEC(vchSalt)
|| u32 nDerivationMethod
|| u32 nDeriveIterations
|| VEC(vchOtherDerivationParameters)
```

Nie ma dodatkowego `nVersion` przed tymi polami. W metodzie historycznej `0` KDF używa `EVP_sha512`; salt ma dokładnie 8 B (`WALLET_CRYPTO_SALT_SIZE`), master key plaintext 32 B, więc `vchCryptedKey` jest typowo 48 B. Domyślne minimum iteracji to 25 000, lecz rzeczywista wartość była kalibrowana czasowo i nie wolno wymagać równości 25 000. `vchOtherDerivationParameters` dla metody 0 jest normalnie pusty (`00`). Komentarz przewidywał metodę 1/scrypt, ale w audytowanych zapisach 2009–2014 jej normalna produkcja nie została potwierdzona: UNKNOWN, nie należy jej udawać obsługiwaną.

Struktura pól pozostaje taka sama w audytowanych wydaniach do `v0.9.3`.

**Materiał prywatny:** zaszyfrowany master key, nie indywidualny EC private key. **Priorytet:** HIGH, bo jest niezbędny do odszyfrowania `ckey`.

### 4.7. `keymeta`

**Pierwsze potwierdzenie kodu:** [`3869fb89…`](https://github.com/bitcoin/bitcoin/commit/3869fb89b60091281b43a35921057ba3f43c18f0), 2013-06-10, `src/walletdb.h::CKeyMetadata`, `WriteKey`, `WriteCryptedKey`, `ReadKeyValue`. Zmiana nie jest w maintenance tagu `v0.8.6`; pierwszy potwierdzony tag wydania to `v0.9.0` (2014).

**Berkeley key:**

```text
STR("keymeta") || VEC(PUB)
```

**Berkeley value w zakresie 2009–2014:**

```text
i32 nVersion       # CURRENT_VERSION == 1
|| i64 nCreateTime # Unix time; 0 oznacza unknown w v0.9.3
```

Nie ma innych pól w wersji 1 z `v0.9.3`. Późniejszy obecny `CKeyMetadata` ma następne wersje i pola HD, ale nie wolno ich narzucać rekordom 2014. Brak `keymeta` jest całkowicie normalny dla 2009–0.8.x. Sam kod wprowadzający metadata zeruje wyliczony birthday, gdy liczba metadata nie odpowiada wszystkim `key` + `ckey`, co dodatkowo potwierdza obsługę niekompletnych starych walletów.

**Materiał prywatny:** nie. **Priorytet:** SUPPORTING.

## 5. Rekordy kontekstowe

Poniższe kształty odnoszą się do logicznego rekordu. Wartości klas złożonych (`CWalletTx`, `CAccountingEntry`) są wersjozależne i nie powinny być w pierwszym decoderze odzyskiwania kluczy rozwijane „na pamięć”. Ich zewnętrzny framing jest potwierdzony; pełne wnętrze należy specyfikować osobnym audytem przed implementacją parsera tych klas.

| Rekord | Berkeley key | Berkeley value w badanym okresie | Uwagi |
|---|---|---|---|
| `pool` | `STR("pool") || i64 index` | `i32 object version || i64 nTime || VEC(PUB)` (`CKeyPool`) | Od [`10384941…`](https://github.com/bitcoin/bitcoin/commit/103849419a9c014a69c76b6f96e48b66cbc838ca), 2010-10-09. Mocny supporting signal. |
| `version` | `STR("version")` | `i32 client/file version` | Obecny od najwcześniejszego audytowanego kodu. Nie utożsamiać samodzielnie z walletem. |
| `minversion` | `STR("minversion")` | `i32 minimum wallet feature version` | Od [`7ec55267…`](https://github.com/bitcoin/bitcoin/commit/7ec552676c66488fe00fb503d02ec4a389a715b7), 2011-07-05. |
| `name` | `STR("name") || STR(address)` | `STR(label/name)` | Od najwcześniejszego kodu; brak private material. |
| `tx` | `STR("tx") || uint256 txid` | serializowany `CWalletTx` | Od najwcześniejszego kodu; wnętrze zmieniało się i jest poza pierwszym key decoderem. |
| `acc` | `STR("acc") || STR(account)` | `i32 object version || VEC(PUB)` (`CAccount`) | Od najwcześniejszego kodu. |
| `acentry` | `STR("acentry") || STR(account) || u64 counter` | `i32 object version || i64 nCreditDebit || i64 nTime || STR(strOtherAccount) || STR(strComment+optional map payload)` | Od [`e4ff4e68…`](https://github.com/bitcoin/bitcoin/commit/e4ff4e6898d378b1a3e83791034a7af455fde3ab), 2010-11-22; szczegóły embedded `mapValue` są wersjozależne. |
| `cscript` | `STR("cscript") || uint160 script_hash` | `VEC(script bytes)` (`CScript`) | Od [`e679ec96…`](https://github.com/bitcoin/bitcoin/commit/e679ec969c8b22c676ebb10bea1038f6c8f13b33), 2011-10-03. |
| `purpose` | `STR("purpose") || STR(address)` | `STR(purpose)` | Od [`a41d5fe0…`](https://github.com/bitcoin/bitcoin/commit/a41d5fe01947f2f878c055670986a165af800f9a), 2013-07-22; potwierdzone w wydaniach od 0.9.0. |
| `orderposnext` | `STR("orderposnext")` | `i64 next_position` | Od [`da7b8c12…`](https://github.com/bitcoin/bitcoin/commit/da7b8c1260d91e3306eb18dd65633567cb31332f), 2012-09-08. |

## 6. Historyczna macierz obecności

Komórka oznacza obecność gałęzi zapisu/odczytu w dokładnie wskazanym anchorze, nie przez cały rok. Dla `wkey` **YES** oznacza potwierdzony loader/format; writer pozostaje UNKNOWN. Anchory: 2009=`v0.1.5`, 2010=`v0.3.19`, pre-0.4=`v0.3.24`, 0.4+=`v0.4.0`, 2012=`v0.6.3`, 2013=`v0.8.6`, 2014=`v0.9.3`.

| Record type | 2009 | 2010 | pre-0.4 2011 | 0.4+ | 2012 | 2013 | 2014 |
|---|---:|---:|---:|---:|---:|---:|---:|
| `key` | YES | YES | YES | YES | YES | YES | YES |
| `wkey` | NO | YES | YES | YES | YES | YES | YES |
| `defaultkey` | YES | YES | YES | YES | YES | YES | YES |
| `ckey` | NO | NO | NO | YES | YES | YES | YES |
| `mkey` | NO | NO | NO | YES | YES | YES | YES |
| `keymeta` | NO | NO | NO | NO | NO | NO | YES |
| `pool` | NO | YES | YES | YES | YES | YES | YES |
| `version` | YES | YES | YES | YES | YES | YES | YES |
| `minversion` | NO | NO | NO | YES | YES | YES | YES |
| `name` | YES | YES | YES | YES | YES | YES | YES |
| `tx` | YES | YES | YES | YES | YES | YES | YES |
| `acc` | YES | YES | YES | YES | YES | YES | YES |
| `acentry` | NO | YES | YES | YES | YES | YES | YES |
| `cscript` | NO | NO | NO | NO | YES | YES | YES |
| `purpose` | NO | NO | NO | NO | NO | NO | YES |
| `orderposnext` | NO | NO | NO | NO | NO | YES | YES |

Nie użyto `UNKNOWN`, ponieważ dla tych konkretnych tagów obecność/nieobecność gałęzi została sprawdzona. Nie oznacza to wiedzy o każdym nieotagowanym buildzie wewnątrz roku.

## 7. Format matrix i recovery priority

| Record | First confirmed source | Last relevant source w zakresie | Berkeley key shape | Berkeley value shape | Private material? | Priority | Notes |
|---|---|---|---|---|---|---|---|
| `key` | `e071a3f6`, 2009-08-30 | `v0.9.3` | `STR(type)||VEC(PUB)` | `VEC(DER)` albo `VEC(DER)||hash32` | plaintext | CRITICAL | Dwa osobne warianty value. |
| `wkey` | `53d50807`, 2010-02-03 | `v0.9.3` loader; `v0.18.1` compatibility | `STR(type)||VEC(PUB)` | W1 lub W2 `CWalletKey` | plaintext | CRITICAL | Writer niepotwierdzony. |
| `defaultkey` | `e071a3f6`, 2009-08-30 | `v0.9.3`; current read-only legacy validation | bare `STR(type)` | `VEC(PUB)` | no | SUPPORTING | Brak suffixu klucza DB. |
| `ckey` | `4e87d341`, 2011-07-08 | `v0.9.3` | `STR(type)||VEC(PUB)` | `VEC(ciphertext)` | encrypted | CRITICAL | Typowo 48 B AES ciphertext. |
| `mkey` | `4e87d341`, 2011-07-08 | `v0.9.3` | `STR(type)||u32 id` | 5 pól `CMasterKey` | encrypted master | HIGH | Konieczny do decrypt `ckey`. |
| `keymeta` | `3869fb89`, 2013-06-10; release `v0.9.0` | `v0.9.3` | `STR(type)||VEC(PUB)` | `i32 version||i64 time` | no | SUPPORTING | Nie istnieje w 0.8.x. |
| `pool` | `10384941`, 2010-10-09 | `v0.9.3` | `STR(type)||i64 index` | `i32||i64||VEC(PUB)` | no | SUPPORTING | Independent pubkey/time evidence. |
| `version` | `e071a3f6`, 2009-08-30 | `v0.9.3` | bare `STR(type)` | `i32` | no | SUPPORTING | Niska unikalność bez korelacji. |
| `minversion` | `7ec55267`, 2011-07-05 | `v0.9.3` | bare `STR(type)` | `i32` | no | SUPPORTING | Nie wymagać przed 0.4. |
| `name` | `e071a3f6`, 2009-08-30 | `v0.9.3` | `STR(type)||STR(address)` | `STR(label)` | no | LOW | Tekst podatny na false positives. |
| `tx` | `e071a3f6`, 2009-08-30 | `v0.9.3` | `STR(type)||hash32` | `CWalletTx` | no | SUPPORTING | Silny dopiero po pełnej walidacji tx. |
| `acc` | `e071a3f6`, 2009-08-30 | `v0.9.3` | `STR(type)||STR(account)` | `i32||VEC(PUB)` | no | SUPPORTING | Legacy account. |
| `acentry` | `e4ff4e68`, 2010-11-22 | `v0.9.3` | `STR(type)||STR(account)||u64` | `CAccountingEntry` | no | LOW | Złożony, wersjozależny comment payload. |
| `cscript` | `e679ec96`, 2011-10-03 | `v0.9.3` | `STR(type)||uint160` | `VEC(script)` | no | SUPPORTING | Walidować hash i script grammar. |
| `purpose` | `a41d5fe0`, 2013-07-22; release `v0.9.0` | `v0.9.3` | `STR(type)||STR(address)` | `STR(purpose)` | no | LOW | Nie istnieje w anchorze 0.8.6. |
| `orderposnext` | `da7b8c12`, 2012-09-08 | `v0.9.3` | bare `STR(type)` | `i64` | no | LOW | Słaby samodzielny sygnał. |

Priority nie jest confidence. Poprawny `mkey` może mieć HIGH recovery priority, ale niskie confidence, jeśli znaleziono tylko przypadkowy niekompletny fragment.

## 8. First/last observed — chronologia zmian

| Data | Commit/tag | Plik / funkcja | Potwierdzona zmiana |
|---|---|---|---|
| 2009-08-30 | [`e071a3f6`](https://github.com/bitcoin/bitcoin/commit/e071a3f6c06f41068ad17134189a4ac3073ef76b) | `db.*`, `key.h`, `serialize.h`; `WriteKey`, `WriteDefaultKey`, `LoadWallet` | `key`, `defaultkey` i podstawowe rekordy walleta; DER `CPrivKey`. |
| 2010-02-03 | [`53d50807`](https://github.com/bitcoin/bitcoin/commit/53d508072b02d522371bde148dcc3e925f472be7) | `db.cpp`, `main.h`; loader, `CWalletKey` | Rozpoznanie `wkey`, wariant W1. |
| 2010-02-23 | [`cb420a1d`](https://github.com/bitcoin/bitcoin/commit/cb420a1dfc23d3c11c5281ed8f7ae003c2f61594) | `main.h::CWalletKey` | Dodanie `strComment`, wariant W2. |
| 2010-10-09 | [`10384941`](https://github.com/bitcoin/bitcoin/commit/103849419a9c014a69c76b6f96e48b66cbc838ca) | `db.*`, `main.*`; `CKeyPool` | `pool`. |
| 2010-11-22 | [`e4ff4e68`](https://github.com/bitcoin/bitcoin/commit/e4ff4e6898d378b1a3e83791034a7af455fde3ab) | `db.*`, `main.h`; accounts | `acentry`. |
| 2011-07-05 | [`7ec55267`](https://github.com/bitcoin/bitcoin/commit/7ec552676c66488fe00fb503d02ec4a389a715b7) | `src/db.*`; `WriteMinVersion`, loader | `minversion`. |
| 2011-07-08 | [`4e87d341`](https://github.com/bitcoin/bitcoin/commit/4e87d341f75f13bbd7d108c31c03886fbc4df56f) | `src/crypter.*`, `keystore.*`, `db.*`, `wallet.*` | Wallet encryption, razem `ckey` i `mkey`. |
| 2011-10-03 | [`e679ec96`](https://github.com/bitcoin/bitcoin/commit/e679ec969c8b22c676ebb10bea1038f6c8f13b33) | `src/db.*`, `script.*` | `cscript`. |
| 2011-11-21 / 2012-02-18 | [`11529c6e`](https://github.com/bitcoin/bitcoin/commit/11529c6e4f7288d8a64c488a726ee3821c7adefe), [`38067c18`](https://github.com/bitcoin/bitcoin/commit/38067c18f8b54c7121643fa3291ffe81b6eefef1) | `src/key.*`, `wallet.cpp` | Compressed pubkeys i feature gate 0.6.0. |
| 2012-09-08 | [`da7b8c12`](https://github.com/bitcoin/bitcoin/commit/da7b8c1260d91e3306eb18dd65633567cb31332f) | `src/walletdb.*`; `WriteOrderPosNext` | `orderposnext`. |
| 2013-06-10 | [`3869fb89`](https://github.com/bitcoin/bitcoin/commit/3869fb89b60091281b43a35921057ba3f43c18f0) | `src/walletdb.*`; `CKeyMetadata`, key writers/loader | `keymeta` v1. |
| 2013-07-22 | [`a41d5fe0`](https://github.com/bitcoin/bitcoin/commit/a41d5fe01947f2f878c055670986a165af800f9a) | `src/walletdb.*`; address book | `purpose`. |
| 2013-08-07 | [`8dc206a1`](https://github.com/bitcoin/bitcoin/commit/8dc206a1e2715be83912e039465a049b708b94c1) | `src/serialize.h::ReadCompactSize` | Odrzucanie nieminimalnych CompactSize; release od 0.9.0. |
| 2013-08-28 | [`6e51b3bd`](https://github.com/bitcoin/bitcoin/commit/6e51b3bddf782f53527cf968445b298ebdec9bbc) | `src/walletdb.*::WriteKey/ReadKeyValue` | Hash `PUB||PRIV_DER` w value `key`; backward-compatible loader; release od 0.9.0. |
| 2014-09-22 | [`v0.9.3`](https://github.com/bitcoin/bitcoin/tree/v0.9.3) | `src/walletdb.*`, `wallet.*` | Ostatni anchor zakresu; oba warianty `key`, `wkey`, encryption i `keymeta` v1. |

## 9. Profile historyczne

### 9.1. `EARLY_UNENCRYPTED_WALLET`

Zakres główny: 2009–pre-0.4 2011.

**Mogą wystąpić:** `key`, `defaultkey`, `version`, `name`, `tx`, `acc`; od 2010 także rozpoznawalny `wkey`, a od późnego 2010 `pool` i `acentry`.

**Private material:** `key` oraz, jeśli rzeczywiście występuje, `wkey`; oba przechowują OpenSSL DER we framingu vectora.

**Nie wolno wymagać:** `ckey`, `mkey`, `keymeta`, `minversion`; dla 2009 również `wkey`, `pool`, `acentry`; dla całego profilu nie należy wymagać `cscript`, `purpose`, `orderposnext` ani compressed pubkey. `defaultkey` jest silnym sygnałem, ale nie globalnym wymogiem kompletności, szczególnie przy carvingu.

**Niezależne sygnały:** poprawny DER i wyprowadzony SEC key równy pubkey z klucza DB; zgodny `defaultkey`; drugi poprawny `key`; poprawny `pool` z pubkey/time; spójny `version`; prawidłowy `tx`/`acc`. Najsilniejszy pojedynczy dowód to kryptograficznie zgodna para `PUB`–`PRIV_DER`, nie napis `key`.

### 9.2. `ENCRYPTED_LEGACY_WALLET`

Zakres: od commit `4e87d341`, release 0.4.0, przez 2014.

- Pełny logiczny encrypted wallet z private keys zwykle ma co najmniej jeden `mkey` oraz jeden lub wiele `ckey`; `mkey` identyfikuje KDF/zaszyfrowany master key, a każdy `ckey` wiąże ciphertext z pubkey.
- Nie wolno odrzucać pojedynczego poprawnego `ckey` lub `mkey` odzyskanego z fragmentu obrazu tylko dlatego, że partner nie został jeszcze znaleziony. Relacja jest wymogiem późniejszego odzyskania/decrypt, nie pierwszego hotspot detection.
- Writer `WriteCryptedKey` usuwa odpowiadające live `key` i `wkey`. W obrazie forensic mogą jednak pozostać stare strony, duplikaty i slack; współwystępowanie plaintext/crypted nie może globalnie unieważniać hotspotu.
- Plaintext/kontekstowe rekordy, takie jak `defaultkey`, `pool`, `name`, `tx`, `acc`, `cscript`, `version` i `minversion`, mogą pozostać.
- `keymeta` jest normalnie nieobecne w encrypted walletach 0.4–0.8.x i pojawia się dopiero w linii 0.9. Brak `keymeta` nie obniża historycznej poprawności profilu pre-0.9.
- Potwierdzenie nie może opierać się na stringach. Wymaga pełnego framingu `ckey`/`mkey`, prawidłowego SEC pubkey, sensownych pól KDF i korelacji rekordów; docelowo odszyfrowania i sprawdzenia pubkey.

## 10. Weryfikacja wcześniejszych założeń BFRS

| Założenie | Werdykt | Dowód / konsekwencja |
|---|---|---|
| Bardzo stare `wallet.dat` mogą mieć `key` bez `ckey`/`mkey`. | **CONFIRMED** | `v0.1.5`, `v0.3.24`; `ckey/mkey` powstały dopiero w `4e87d341`. |
| `defaultkey` występuje w bardzo starych walletach. | **CONFIRMED** | Writer i loader od `e071a3f6`, obecny w `v0.1.5`. |
| `wkey` jest historycznym formatem. | **PARTIALLY CONFIRMED** | Klasa i loader od `53d50807`, późniejsza kompatybilność do 0.18; normalny writer i realna częstość występowania nie zostały potwierdzone. |
| `ckey`/`mkey` są związane z wallet encryption. | **CONFIRMED** | Oba wprowadzone razem w `4e87d341`; `EncryptWallet`, `WriteCryptedKey`, `WriteMasterKey`. |
| `keymeta` nie powinno być wymagane globalnie. | **CONFIRMED** | Brak do linii 0.8.x; pierwszy release z rekordem to 0.9.0. |

Jawnie obalone lub skorygowane uproszczenia:

- „plaintext private key to raw 32 B” — **INCORRECT**; `key`/`wkey` mają DER `CPrivKey`; raw 32 B `CSecret` jest wejściem do encryption `ckey`.
- „jeden format value `key` dla całego okresu” — **INCORRECT**; od linii 0.9 writer dodaje hash, loader nadal czyta stary wariant.
- „canonical CompactSize rules były takie same od 2009” — **INCORRECT** dla readera; writer był minimalny, ale stary reader nie odrzucał nieminimalnych form.
- „33/65 B wystarczy do rozpoznania pubkey” — **INCORRECT**; wymagane są framing, SEC i walidacja krzywej.
- „`wkey` był normalnie zapisywany przez znany writer” — **NOT CONFIRMED**.

## 11. Implementation rules for BFRS 2.0

1. Pierwszy `BitcoinCoreRecordTypeDecoder` ma rozpoznawać co najmniej: `key`, `wkey`, `defaultkey`, `ckey`, `mkey`, `keymeta`, `pool`, `version`, `minversion`, `name`, `tx`, `acc`, `acentry`, `cscript`, `purpose`, `orderposnext`.
2. Nazwa typu musi być odczytana jako `STR(type)` od granicy logicznego klucza Berkeley DB. Nie skanować samego ASCII bez CompactSize.
3. Po typie decoder ma zastosować dokładny suffix: brak dla bare types; `VEC(PUB)` dla key-family; `u32` dla `mkey`; `i64` dla `pool`; odpowiednie string/hash dla rekordów kontekstowych.
4. Wspólne dla 2009–2014 są: framing string/vector, konkatenacja pól `pair/tuple`, rozpoznanie SEC65 i SEC33, oraz potrzeba pełnej konsumpcji logicznego klucza/value.
5. Parser CompactSize ma zwracać co najmniej `value`, `bytes_consumed`, `canonical`. Tryb historical recovery może zaakceptować nieminimalny odczyt ze statusem ostrzegawczym; strict writer validation może go odrzucić.
6. Nie stosować globalnie: obecności `ckey`, `mkey`, `keymeta`, `defaultkey`, compressed pubkey, hash suffixu `key`, canonical-reader rule z 0.9 ani jednej długości DER.
7. Dla `key` potrzebne są osobne warianty `LegacyPlainKeyV1` (DER only) i `LegacyPlainKeyV2` (DER + hash32), z jednoznacznym rozpoznaniem przez dokładną pozostałą długość i weryfikację hash.
8. Dla `wkey` potrzebne są warianty W1 i W2. Nie zgadywać brakującego `strComment`; wykrywać przez pełne parsowanie i granicę rekordu.
9. Dla `keymeta` pierwszy validator powinien obsługiwać wyłącznie v1 z 2014. Nowsze wersje muszą być delegowane do osobnego parsera, nie traktowane jako corrupt v1.
10. Aby uniknąć false negatives 2009–2010, profil ma przyznawać najwyższą wartość poprawnej kryptograficznie parze `key(PUB)->DER`, nawet bez wszystkich rekordów pomocniczych.
11. Aby uniknąć false positives, wymagane są: pełny type prefix, poprawny suffix DB key, ograniczone długości, pełna konsumpcja value, DER/SEC validation oraz — dla `key` — zgodność wyprowadzonego pubkey i opcjonalnego hash.
12. Docelowej walidacji kryptograficznej wymagają: `key`, `wkey`, `ckey`+`mkey`; `defaultkey`, `pool`, `keymeta` wymagają walidacji SEC i relacji pubkey. `cscript` powinien sprawdzać hash skryptu.
13. Confidence ma wynikać z niezależnych dowodów i relacji, nigdy z recovery priority ani z samej nazwy typu.
14. Parser nie powinien zakładać, że znaleziony fragment pochodzi z aktywnego rekordu B-tree; stare/free pages są oczekiwanym źródłem duplikatów i mieszanych generacji.

## 12. Minimalny plan przyszłych validatorów (bez implementacji)

```text
BitcoinCoreRecordTypeDecoder
├── CompactSize/String/Vector framing layer
├── LegacyPlainKeyValidator
│   ├── DER-only variant
│   └── DER+keypair-hash variant
├── LegacyWalletKeyValidator
│   ├── CWalletKey W1
│   └── CWalletKey W2
├── DefaultKeyValidator
├── CryptedKeyValidator
├── MasterKeyValidator
├── KeyMetadataV1Validator
├── KeyPoolValidator
└── SupportingRecordValidator(s)
    ├── fixed-shape: version/minversion/orderposnext
    ├── string-keyed: name/purpose/acc
    └── deferred complex: tx/acentry/cscript
```

Warstwę DER/SEC/secp256k1 należy współdzielić między `key`, `wkey`, `defaultkey`, `ckey`, `keymeta`, `pool` i `acc`. `CryptedKeyValidator` może wykonać framing bez passphrase; osobny późniejszy `EncryptedKeysetValidator` powinien skorelować `mkey`, odszyfrować master key, odszyfrować `ckey` i odtworzyć pubkey.

## 13. Plan syntetycznych test vectors

Nie umieszczać prawdziwych kluczy użytkownika. Przyszłe fixtures mają używać jawnie testowych, deterministycznych danych lub samych structural placeholders; na tym etapie niczego nie generuje się.

| Typ / wariant | Plan pozytywnego wektora | Kluczowe negatywne warianty |
|---|---|---|
| `key` K1 SEC65 | `03||key || 41||dummy-valid-SEC65`; value `CS(der_len)||dummy-valid-test-DER` | raw32 zamiast DER, zły DER, niespójny PUB, truncation, trailing byte |
| `key` K1 SEC33 | jw. z `21||dummy-valid-SEC33` | 33 B z prefiksem innym niż 02/03, punkt poza krzywą |
| `key` K2 | K1 + 32 B testowego `Hash(PUB_raw||DER_raw)` | hash nad framed bytes, odwrócony hash, 31/33 B suffix |
| `wkey` W1 | `04||wkey||VEC(PUB)`; `i32||VEC(DER)||i64||i64` | brak version/time, value błędnie traktowane jak zwykły `key` |
| `wkey` W2 | W1 + `STR(dummy_comment)` | brak length comment, trailing bytes, W1 błędnie wymagający comment |
| `defaultkey` | bare `0a||defaultkey`; value `VEC(valid test PUB)` | trailing key field, DER w value, niepoprawny SEC |
| `ckey` | `04||ckey||VEC(PUB)`; value `30||48 dummy ciphertext bytes` | sam ASCII, ciphertext 0/31/47/49 B, zły SEC, brak framingu vectora |
| `mkey` | `04||mkey||u32 id`; value `30||48 cipher || 08||8 salt || u32 method0 || u32 iterations || 00` | CompactSize id, zły salt, zero iterations, missing other-params vector, trailing bytes |
| `keymeta` v1 | `07||keymeta||VEC(PUB)`; value `i32(1)||i64(time/0)` | wymaganie rekordu w profilu 0.8, nieznana wersja parsowana jak v1, zły PUB |
| `pool` | `04||pool||i64 index`; value `i32||i64 time||VEC(PUB)` | u32/CompactSize index, zły PUB, ucięty object version |
| bare fixed records | pełne prefiksy `version`, `minversion`, `orderposnext` + odpowiednio i32/i32/i64 value | trailing suffix w key, zła szerokość value |
| string records | pełny `STR(type)||STR(key_text)` i framed string value | przypadkowy ASCII bez length, nierealne długości, truncation |

Każda rodzina powinna mieć także parę CompactSize: kanoniczny pozytywny oraz nieminimalny oznaczany jako `legacy-reader-accepted/noncanonical`, a nie bezwarunkowo identyczny z poprawnym writer output.

## 14. Obecna kompatybilność jako kontrola, nie specyfikacja historyczna

Obecny [`src/wallet/walletdb.cpp`](https://github.com/bitcoin/bitcoin/blob/master/src/wallet/walletdb.cpp) nadal:

- czyta stary `key` bez hash i nowy z hash;
- ładuje `ckey`, `mkey`, `keymeta` i waliduje legacy `defaultkey`;
- klasyfikuje legacy types osobno;
- jawnie odrzuca `wkey` z komunikatem migracji przez 0.18.

Obecny [`src/wallet/migrate.cpp`](https://github.com/bitcoin/bitcoin/blob/master/src/wallet/migrate.cpp) zawiera własny read-only parser stron Berkeley DB do migracji. To potwierdza potrzebę historycznej kompatybilności na poziomie storage, ale nie zmienia opisanych wyżej formatów logicznych. BFRS ma implementować specyfikację z historycznych źródeł, nie kopiować założeń current-only.

## 15. Otwarte kwestie i granice audytu

- Normalny writer `wkey`, realna częstość jego występowania i dokładny moment zaprzestania zapisu: **UNKNOWN**. Loader i dwa warianty struktury są potwierdzone.
- Metoda `CMasterKey::nDerivationMethod == 1` była komentowana jako scrypt, ale normalny writer/parametry w badanych wydaniach nie zostały potwierdzone: **UNKNOWN**.
- Wnętrze wszystkich historycznych wariantów `CWalletTx` i embedded payload `CAccountingEntry::strComment/mapValue` wymaga oddzielnego audytu przed pełnym parserem tych rekordów. Nie jest potrzebne do pierwszego key recovery decoder.
- Typowa długość DER 279 B jest potwierdzona komentarzem/kodem epoki, lecz ścisły zakres wszystkich możliwych wyjść różnych historycznych OpenSSL nie został zakodowany w źródle jako invariant: nie używać jako jedynego kryterium.
- „Last relevant” w tabeli oznacza ostatni anchor 2009–2014 (`v0.9.3`), nie commit usuwający rekord w późniejszych dekadach.

## 16. Konkluzja

Plan dekodowania nazwy rekordu przez CompactSize jest zgodny z całym audytowanym okresem 2009–2014, pod warunkiem zachowania różnicy między kanonicznym outputem writera a liberalnym starym readerem. Pierwsza implementacja musi mieć osobne historyczne parsery dla `key` K1/K2, `wkey` W1/W2, `ckey`, `mkey` i `keymeta` v1. Najstarsze portfele należy rozpoznawać przede wszystkim przez kryptograficznie spójny `key(PUB)->CPrivKey DER`, bez wymagań `ckey`, `mkey`, `keymeta` lub compressed pubkey.
