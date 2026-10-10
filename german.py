"""Generator of WWII-style German military radio messages.

Messages are written as German words and normalised to Enigma conventions:
uppercase A-Z only, X for a full stop, ZZ for a comma, Q for CH, umlauts as
AE/OE/UE, numbers spelled out (ZWO for a standalone two).

`message(rng, min_len, max_len)` returns one normalised message whose length is
in [min_len, max_len]: a header followed by clauses drawn from the message
type's pool (and a shared pool), plus an optional closer.
"""

import random

ONES = ["NULL", "EINS", "ZWEI", "DREI", "VIER", "FUENF", "SECHS", "SIEBEN", "ACHT", "NEUN",
        "ZEHN", "ELF", "ZWOELF", "DREIZEHN", "VIERZEHN", "FUENFZEHN", "SECHZEHN", "SIEBZEHN",
        "ACHTZEHN", "NEUNZEHN"]
TENS = {2: "ZWANZIG", 3: "DREISSIG", 4: "VIERZIG", 5: "FUENFZIG", 6: "SECHZIG", 7: "SIEBZIG",
        8: "ACHTZIG", 9: "NEUNZIG"}
DIGITS = ["NULL", "EINS", "ZWO", "DREI", "VIER", "FUENF", "SECHS", "SIEBEN", "ACHT", "NEUN"]

ORDINALS = ["ERSTE", "ZWEITE", "DRITTE", "VIERTE", "FUENFTE", "SECHSTE", "SIEBTE", "ACHTE",
            "NEUNTE", "ZEHNTE", "ELFTE", "ZWOELFTE", "DREIZEHNTE", "VIERZEHNTE", "FUENFZEHNTE",
            "SECHZEHNTE", "SIEBZEHNTE", "ACHTZEHNTE", "NEUNZEHNTE", "ZWANZIGSTE"]

MONTHS = ["JANUAR", "FEBRUAR", "MAERZ", "APRIL", "MAI", "JUNI", "JULI", "AUGUST", "SEPTEMBER",
          "OKTOBER", "NOVEMBER", "DEZEMBER"]

PHONETIC = ["ANTON", "BERTA", "CAESAR", "DORA", "EMIL", "FRIEDRICH", "GUSTAV", "HEINRICH", "IDA",
            "JULIUS", "KAUFMANN", "LUDWIG", "MARTHA", "NORDPOL", "OTTO", "PAULA", "QUELLE",
            "RICHARD", "SIEGFRIED", "THEODOR", "ULRICH", "VIKTOR", "WILHELM", "XANTHIPPE",
            "YPSILON", "ZACHARIAS"]

DIRECTIONS = ["NORD", "NORDOST", "OST", "SUEDOST", "SUED", "SUEDWEST", "WEST", "NORDWEST"]

TOWNS = ["BREST", "LORIENT", "KIEL", "WILHELMSHAVEN", "BREMEN", "HAMBURG", "BERGEN", "NARVIK",
         "TRONDHEIM", "ROSTOCK", "DANZIG", "STETTIN", "CHERBOURG", "CALAIS", "DIJON", "ORLEANS",
         "ROUEN", "AMIENS", "REIMS", "METZ", "LILLE", "SMOLENSK", "KALININ", "ORSCHA", "WJASMA",
         "BRJANSK", "KURSK", "CHARKOW", "POLTAWA", "SHITOMIR", "MINSK", "PLESKAU", "NOWGOROD",
         "TOBRUK", "BENGASI", "DERNA", "SOLLUM", "TRIPOLIS", "CATANIA", "MESSINA", "NEAPEL",
         "BELGRAD", "SALONIKI", "ATHEN", "KRAKAU", "LEMBERG", "WARSCHAU", "KOENIGSBERG"]
SEAS = ["NORDATLANTIK", "MITTELATLANTIK", "NORDSEE", "OSTSEE", "NORDMEER", "MITTELMEER",
        "BISKAYA", "KANAL", "SKAGERRAK", "BARENTSSEE"]
REGIONS = ["NORDABSCHNITT", "SUEDABSCHNITT", "MITTELABSCHNITT", "KUESTENABSCHNITT", "BRUECKENKOPF",
           "OSTFRONT", "WESTFRONT", "HAFENGEBIET", "FLUGPLATZBEREICH"]

UNITS = ["KOMPANIE", "BATTERIE", "DIVISION", "PANZERDIVISION", "INFANTERIEDIVISION",
         "GEBIRGSDIVISION", "BRIGADE", "ARMEE", "PANZERARMEE", "LUFTFLOTTE", "FLOTTILLE",
         "SCHWADRON", "STAFFEL"]
RANKS = ["LEUTNANT", "OBERLEUTNANT", "HAUPTMANN", "MAJOR", "OBERSTLEUTNANT", "OBERST",
         "GENERALMAJOR", "KAPITAENLEUTNANT", "KORVETTENKAPITAEN", "FREGATTENKAPITAEN"]
NAMES = ["MUELLER", "SCHMIDT", "SCHNEIDER", "FISCHER", "WEBER", "MEYER", "WAGNER", "BECKER",
         "SCHULZ", "HOFFMANN", "KOCH", "RICHTER", "KLEIN", "WOLF", "NEUMANN", "SCHWARZ",
         "ZIMMERMANN", "BRAUN", "KRUEGER", "HARTMANN", "LANGE", "WERNER", "KRAUSE", "LEHMANN"]


def number(n: int) -> str:
    """German cardinal for 0 <= n <= 9999; a standalone two is ZWO."""
    if n == 2:
        return "ZWO"
    return _number(n, standalone=True)


def _number(n: int, standalone: bool) -> str:
    if n < 20:
        if n == 1 and not standalone:
            return "EIN"
        return ONES[n]
    if n < 100:
        tens, ones = divmod(n, 10)
        return (ONES[ones] if ones != 1 else "EIN") + "UND" + TENS[tens] if ones else TENS[tens]
    if n < 1000:
        hundreds, rest = divmod(n, 100)
        return _number(hundreds, False) + "HUNDERT" + (_number(rest, True) if rest else "")
    thousands, rest = divmod(n, 1000)
    return _number(thousands, False) + "TAUSEND" + (_number(rest, True) if rest else "")


def digits(s: str) -> str:
    return " ".join(DIGITS[int(d)] for d in s)


def ordinal_day(d: int) -> str:
    """Dative ordinal used in dates: AM DRITTEN, AM ZWANZIGSTEN."""
    if d <= 19:
        return ORDINALS[d - 1] + "N"
    return _number(d, False) + "STEN"


class Slots:
    """Random slot fillers bound to one RNG."""

    def __init__(self, rng: random.Random):
        self.r = rng

    def n(self, lo, hi):
        return number(self.r.randint(lo, hi))

    def time(self):
        h = self.r.randint(0, 23)
        m = self.r.choice([0, 0, 15, 30, 45, 10, 20, 40, 50])
        return f"{number(h)} UHR" + (f" {number(m)}" if m else "")

    def date(self):
        return f"{ordinal_day(self.r.randint(1, 28))} {self.r.choice(MONTHS)}"

    def grid(self):
        a, b = self.r.sample(PHONETIC, 2)
        return f"{a} {b} {digits(str(self.r.randint(1000, 9999)))}"

    def course(self):
        return digits(f"{self.r.randint(0, 359):03d}")

    def unit(self):
        return f"{self.r.choice(ORDINALS[:12])} {self.r.choice(UNITS)}"

    def town(self):
        return self.r.choice(TOWNS)

    def sea(self):
        return self.r.choice(SEAS)

    def region(self):
        return self.r.choice(REGIONS)

    def dir(self):
        return self.r.choice(DIRECTIONS)

    def officer(self):
        return f"{self.r.choice(RANKS)} {self.r.choice(NAMES)}"

    def pick(self, *options):
        return self.r.choice(options)


# Each message type: header templates and clause templates. A template is a
# function of Slots returning German text with spaces and punctuation.
TYPES = {
    "wetter": {
        "headers": [
            lambda s: "WETTERBERICHT",
            lambda s: "SEEWETTERBERICHT",
            lambda s: "WETTERMELDUNG",
            lambda s: "WETTERWARNUNG",
            lambda s: f"WETTERVORHERSAGE FUER {s.town()}",
            lambda s: f"WETTERLAGE {s.region()}",
        ],
        "clauses": [
            lambda s: f"WIND AUS {s.dir()} STAERKE {s.n(1, 9)}",
            lambda s: f"SEEGANG {s.n(1, 8)}",
            lambda s: f"SICHT {s.n(1, 30)} KILOMETER",
            lambda s: f"SICHT UNTER {s.n(1, 5)} SEEMEILEN",
            lambda s: f"BEWOELKUNG {s.n(1, 10)} ZEHNTEL",
            lambda s: s.pick("BEDECKT", "HEITER", "LEICHTER REGEN", "STARKER REGEN", "SCHNEEFALL",
                             "GEWITTERNEIGUNG", "KLARER HIMMEL", "DUNST UEBER SEE"),
            lambda s: f"NEBEL BIS {s.time()}",
            lambda s: f"LUFTDRUCK {s.n(960, 1040)} MILLIBAR {s.pick('FALLEND', 'STEIGEND', 'GLEICHBLEIBEND')}",
            lambda s: f"TEMPERATUR {s.n(0, 30)} GRAD",
            lambda s: f"TEMPERATUR MINUS {s.n(1, 30)} GRAD",
            lambda s: f"FROST IN DER NACHT BIS MINUS {s.n(1, 25)} GRAD",
            lambda s: f"VORHERSAGE FUER MORGEN {s.pick('AUFHEITERND', 'ZUNEHMEND BEWOELKT', 'STURM AUS ' + s.dir())}",
            lambda s: f"TIEFDRUCKGEBIET UEBER {s.sea()} ZIEHT NACH {s.dir()}",
            lambda s: f"FLUGWETTER {s.pick('GUT', 'MAESSIG', 'SCHLECHT')} IM {s.region()}",
        ],
    },
    "uboot": {
        "headers": [
            lambda s: "VON BEFEHLSHABER DER UBOOTE",
            lambda s: "AN ALLE UBOOTE",
            lambda s: "GELEITZUG GESICHTET",
            lambda s: "ERFOLGSBERICHT",
            lambda s: "FEINDMELDUNG",
            lambda s: "STANDORTMELDUNG",
        ],
        "clauses": [
            lambda s: f"GELEITZUG IN QUADRAT {s.grid()}",
            lambda s: f"{s.n(3, 40)} DAMPFER UND {s.n(1, 9)} ZERSTOERER",
            lambda s: f"KURS {s.course()} FAHRT {s.n(5, 18)} KNOTEN",
            lambda s: f"{s.n(1, 5)} SCHIFFE VERSENKT ZUSAMMEN {s.n(3, 40)} TAUSEND TONNEN",
            lambda s: f"WASSERBOMBENVERFOLGUNG {s.n(1, 12)} STUNDEN",
            lambda s: f"BRENNSTOFF {s.n(5, 120)} KUBIKMETER",
            lambda s: f"NOCH {s.n(1, 14)} TORPEDOS AN BORD",
            lambda s: f"STEHE IN QUADRAT {s.grid()}",
            lambda s: f"OPERIERE IM {s.sea()}",
            lambda s: "ERBITTE NEUES OPERATIONSGEBIET",
            lambda s: f"ANGRIFF IN DER NACHT ZUM {s.date()}",
            lambda s: f"FUEHLUNG VERLOREN UM {s.time()}",
            lambda s: f"RUECKMARSCH NACH {s.pick('BREST', 'LORIENT', 'KIEL', 'BERGEN', 'TRONDHEIM')}",
            lambda s: f"FLUGZEUG ZWINGT ZUM TAUCHEN IN QUADRAT {s.grid()}",
        ],
    },
    "befehl": {
        "headers": [
            lambda s: f"BEFEHL NUMMER {digits(str(s.r.randint(10, 999)))}",
            lambda s: "VERTEIDIGUNGSBEFEHL",
            lambda s: "AUFKLAERUNGSBEFEHL",
            lambda s: "ANGRIFFSBEFEHL",
            lambda s: f"AN {s.unit()}",
            lambda s: f"GEHEIME KOMMANDOSACHE",
        ],
        "clauses": [
            lambda s: f"{s.unit()} VERLEGT NACH {s.town()}",
            lambda s: f"{s.unit()} GREIFT AM {s.date()} UM {s.time()} AN",
            lambda s: "ALLE EINHEITEN HALTEN STELLUNG",
            lambda s: f"BEREITSCHAFT BIS {s.time()}",
            lambda s: f"FUNKSTILLE VON {s.time()} BIS {s.time()}",
            lambda s: f"ERGEBNIS MELDEN BIS {s.time()}",
            lambda s: f"{s.unit()} ERKUNDET STRASSEN NACH {s.dir()}",
            lambda s: f"TREFFPUNKT {s.town()}",
            lambda s: f"RUECKZUG NACH {s.town()} {s.pick('GENEHMIGT', 'NICHT GENEHMIGT')}",
            lambda s: f"SPERRE DIE BRUECKE BEI {s.town()}",
            lambda s: f"ABMARSCH AM {s.date()}",
            lambda s: f"GEFECHTSSTAND IN {s.town()}",
            lambda s: f"ANGRIFFSZIEL HOEHE {s.n(100, 900)}",
        ],
    },
    "lage": {
        "headers": [
            lambda s: "LAGEBERICHT",
            lambda s: "FEINDLAGEBERICHT",
            lambda s: "VERLUSTMELDUNG",
            lambda s: "GEFECHTSBERICHT",
            lambda s: f"TAGESMELDUNG {s.unit()}",
            lambda s: f"LAGE IM {s.region()}",
        ],
        "clauses": [
            lambda s: f"MUNITION FUER {s.n(1, 9)} TAGE",
            lambda s: f"VERPFLEGUNG {s.pick('GESICHERT', 'KNAPP', 'FUER ' + s.n(2, 9) + ' TAGE')}",
            lambda s: f"{s.n(1, 40)} TOTE {s.n(1, 90)} VERWUNDETE {s.n(1, 20)} VERMISSTE",
            lambda s: f"FEIND MIT {s.n(2, 60)} PANZERN BEI {s.town()}",
            lambda s: f"STARKER ARTILLERIEBESCHUSS SEIT {s.time()}",
            lambda s: "EIGENE STELLUNGEN GEHALTEN",
            lambda s: f"BRUECKE BEI {s.town()} ZERSTOERT",
            lambda s: f"{s.n(5, 400)} GEFANGENE EINGEBRACHT",
            lambda s: f"PERSONALSTAERKE {s.n(80, 900)} MANN",
            lambda s: f"FEINDLICHE LUFTTAETIGKEIT {s.pick('GERING', 'LEBHAFT', 'STARK')}",
            lambda s: f"STOSSTRUPP NACH {s.dir()} ABGEWIESEN",
            lambda s: f"{s.unit()} IN {s.town()} EINGETROFFEN",
            lambda s: f"STRASSE NACH {s.town()} VERMINT",
        ],
    },
    "misc": {
        "headers": [
            lambda s: "SONDERMELDUNG",
            lambda s: "NACHSCHUBMELDUNG",
            lambda s: "FUNKSPRUCH",
            lambda s: "DRINGEND",
            lambda s: f"AN KOMMANDEUR {s.unit()}",
            lambda s: "ZUGMELDUNG",
        ],
        "clauses": [
            lambda s: f"NACHSCHUB TRIFFT AM {s.date()} IN {s.town()} EIN",
            lambda s: f"ERBITTE {s.n(5, 300)} TONNEN BETRIEBSSTOFF",
            lambda s: f"{s.n(2, 40)} LASTKRAFTWAGEN AUSGEFALLEN",
            lambda s: f"NEUE FUNKFREQUENZ {s.n(2000, 9000)} KILOHERTZ AB {s.time()}",
            lambda s: f"LAZARETTZUG AB {s.town()} UM {s.time()}",
            lambda s: f"QUARTIER IN {s.town()} BEZOGEN",
            lambda s: f"ERSATZTEILE FUER {s.n(3, 30)} PANZER ANGEFORDERT",
            lambda s: f"POST FUER {s.unit()} LIEGT IN {s.town()}",
            lambda s: f"URLAUBSSPERRE BIS {s.date()}",
            lambda s: f"MELDEKOPF IN {s.town()} EINGERICHTET",
        ],
    },
}

SHARED_CLAUSES = [
    lambda s: f"STANDORT {s.town()}",
    lambda s: f"UHRZEIT {s.time()}",
    lambda s: f"BEZUG FUNKSPRUCH VOM {s.date()}",
    lambda s: "WEITERE MELDUNG FOLGT",
]

CLOSERS = [
    lambda s: "ENDE",
    lambda s: "ERBITTE BESTAETIGUNG",
    lambda s: f"MELDEN BIS {s.time()}",
    lambda s: s.officer(),
    lambda s: f"GEZEICHNET {s.officer()}",
    lambda s: "KOMMANDANT",
]


def normalise(text: str) -> str:
    """German text with spaces and punctuation -> Enigma plaintext."""
    t = text.upper().replace("Ä", "AE").replace("Ö", "OE").replace("Ü", "UE").replace("ß", "SS")
    t = t.replace("CH", "Q").replace(".", "X").replace(",", "ZZ").replace(":", "X")
    return "".join(c for c in t if "A" <= c <= "Z")


def message(rng: random.Random, min_len: int, max_len: int, kind: str = None) -> str:
    """One normalised message with min_len <= len <= max_len."""
    for _ in range(200):
        kind_ = kind or rng.choice(sorted(TYPES))
        s = Slots(rng)
        parts = [rng.choice(TYPES[kind_]["headers"])(s)]
        pool = TYPES[kind_]["clauses"] + SHARED_CLAUSES
        closer = rng.choice(CLOSERS)(s) if rng.random() < 0.7 else None
        used = {}
        target = rng.randint(min_len, max_len)
        while True:
            text = normalise(". ".join(parts + ([closer] if closer else [])) + ".")
            if len(text) >= target:
                break
            options = [i for i in range(len(pool)) if used.get(i, 0) < 2]
            if not options:
                break
            i = rng.choice(options)
            used[i] = used.get(i, 0) + 1
            parts.append(pool[i](s))
        if min_len <= len(text) <= max_len:
            return text
    raise RuntimeError(f"could not generate a message of {min_len}-{max_len} letters")


def sample_corpus(rng: random.Random, n_chars: int) -> str:
    """Newline-separated messages of mixed lengths, about n_chars in total."""
    out, total = [], 0
    while total < n_chars:
        lo = rng.choice([60, 100, 200, 300])
        m = message(rng, lo, lo + 100)
        out.append(m)
        total += len(m) + 1
    return "\n".join(out) + "\n"
