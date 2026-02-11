app.py — to rdzeń aplikacji.
Jest tam cała logika: trasy (/login, /problems), praca z bazą danych, logowanie, obsługa formularzy, role admin/użytkownik, komentarze, archiwum, upload plików itd.

templates/ — strony WWW (szablony HTML), czyli to co użytkownik widzi w przeglądarce.

static/ — wygląd i frontend: CSS, obrazki, ikony, pliki JS.

uploads/ — pliki przesyłane przez użytkowników (screeny, wideo, dokumenty).

migrations/ — migracje bazy danych (historia zmian schematu, Flask-Migrate/Alembic).

instance/ — tu jest baza danych site.db 

requirements.txt — lista bibliotek do instalacji na innym komputerze.

app.spec — plik do budowania .exe przez PyInstaller.

env/ — środowisko wirtualne Pythona (zainstalowane biblioteki). (Pojawia się przy uruchomieniu projektu)

__pycache__/ — cache Pythona, można usuwać.	(Pojawia się przy uruchomieniu projektu)