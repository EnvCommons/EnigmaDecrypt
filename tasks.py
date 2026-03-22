"""
Task corpus for the Enigma Decrypt environment.

60 realistic WWII German military messages across 5 categories:
- Weather reports (WETTER)
- U-boat reports (UBOOT)
- Operational orders (BEFEHL)
- Status reports (LAGEBERICHT)
- Miscellaneous (MISC)

Each task is encrypted with specific Enigma settings and includes
difficulty-appropriate cribs and revealed information.

Message conventions:
- Uppercase A-Z only
- X = period/stop
- ZZ = comma
- Q replaces CH (e.g., NICHT -> NIQT)
- Numbers spelled out in German
"""

import json
import random
from pathlib import Path
from enigma_machine import EnigmaMachine

# ---------------------------------------------------------------------------
# Message corpus: realistic WWII German military messages
# ---------------------------------------------------------------------------

MESSAGES = [
    # --- WEATHER REPORTS (12) ---
    {
        "id": "wetter_001",
        "category": "WETTER",
        "plaintext": "WETTERBERIQTXWINDSTAERKEDREIAUSNORDWESTXBEWOELKTXSIQTUNTERFUENFKILOMETERX",
        "context": "Intercepted Luftwaffe weather report from a coastal observation post in northern France, 0600 hours.",
    },
    {
        "id": "wetter_002",
        "category": "WETTER",
        "plaintext": "WETTERVORHERSAGEXLEIQTERREGENVONWESTENERWARTETZZMITTAGSAUFKLARUNGMOEGLIX",
        "context": "Daily weather forecast intercepted from Army Group B headquarters, transmitted at dawn.",
    },
    {
        "id": "wetter_003",
        "category": "WETTER",
        "plaintext": "WETTERLAGENORDSEEXWINDSTAERKEFUENFAUSNORDXWELLENHOEHEDREIBISVIERMETERZZSIQTGUTX",
        "context": "Naval weather report from a Kriegsmarine station on the North Sea coast.",
    },
    {
        "id": "wetter_004",
        "category": "WETTER",
        "plaintext": "WETTERMELDUNGXTEMPERATURZWOELFGRADXLUFTDRUQEINSTAUSENDUNDZWANZIGMILLIBARXNEBELBISZEHNUHRX",
        "context": "Morning weather observation from a Wehrmacht airfield in Belgium.",
    },
    {
        "id": "wetter_005",
        "category": "WETTER",
        "plaintext": "WETTERBERIQTFUERSTATIONBREMENXBEDEQTXNIESELREGENXSIQTUNTEREINSKOMMAZWEIKILOMETERX",
        "context": "Station weather report intercepted from Bremen area, relayed to Luftwaffe command.",
    },
    {
        "id": "wetter_006",
        "category": "WETTER",
        "plaintext": "SEEWETTERBERIQTXWINDNORDOSTZZSEEGANGLEIQQXSIQTGUTXFUENFSEEMEILENXBAROMETERSTEIGENDX",
        "context": "Maritime weather report from a U-boat weather buoy in the North Atlantic.",
    },
    {
        "id": "wetter_007",
        "category": "WETTER",
        "plaintext": "WETTERLAGEOSTFRONTXSTARKERFROSTERWARTETZZTEMPERATURBISMINUSZWANZIGGRADUNTERX",
        "context": "Eastern Front weather advisory, December 1942, transmitted to Army Group Center.",
    },
    {
        "id": "wetter_008",
        "category": "WETTER",
        "plaintext": "WETTERVORHERSAGEFUERMITTELMEERSEKTORXAUFKLARUNGZZTEMPERATURDREIUNDZWANZIGGRADUNDWAERMX",
        "context": "Mediterranean sector weather forecast from Fliegerkorps X headquarters.",
    },
    {
        "id": "wetter_009",
        "category": "WETTER",
        "plaintext": "MORGENWETTERBERIQTXWOLKENUNTERGRENZEFUENFHUNDERTMETERXLEIQQTERSCHNEEFALLSEITDREIUHRX",
        "context": "Early morning weather report from a forward observation post, Eastern Front.",
    },
    {
        "id": "wetter_010",
        "category": "WETTER",
        "plaintext": "NAQTWITTERUNGSBERIQTXKLAREHIMMELXMONDLIQTGUTXSIQTWEITERDREISSIGKILOMETERX",
        "context": "Night weather report relevant to bomber operations, intercepted from Luftflotte 3.",
    },
    {
        "id": "wetter_011",
        "category": "WETTER",
        "plaintext": "WETTERWARNUNGXSTARKERGEWITTERVONSUEDWESTENIMANZUGXALLEFLUGOPERATIONENEINSTELLENX",
        "context": "Urgent weather warning intercepted from tactical air command.",
    },
    {
        "id": "wetter_012",
        "category": "WETTER",
        "plaintext": "WETTERBERIQTATLANTIKXWINDSTAERKESIEBENZZSEEGANGRAUQXSIQTUNTERZWEISEEMEILENX",
        "context": "Atlantic weather report from a Kriegsmarine long-range reconnaissance aircraft.",
    },

    # --- U-BOAT REPORTS (12) ---
    {
        "id": "uboot_001",
        "category": "UBOOT",
        "plaintext": "ANBEFEHLSHABERDERVBOOTEXKEINEFEINDBERUERUNGXQUADRATAQTDREINEUNSIEBENXKURSSUEDSUESTWESXFAHRTAQTKNOTEN",
        "context": "U-boat patrol report to BdU (Commander of Submarines), reporting no enemy contact.",
    },
    {
        "id": "uboot_002",
        "category": "UBOOT",
        "plaintext": "GELEITZUGGESIQTETXQUADRATBERTAVIERFUENFXKURSOSTNORDOSTXGESQAETZTZWANZIGFAQRZEUGEX",
        "context": "Convoy sighting report from a U-boat on patrol in the North Atlantic.",
    },
    {
        "id": "uboot_003",
        "category": "UBOOT",
        "plaintext": "TORPEDOANGRIFFXZWEITREFFERAUFDREITAUSENDTONNERXSIQVERSTEXMANNAQAFTWOHLAUFX",
        "context": "Attack report from a U-boat, claiming hits on a cargo vessel.",
    },
    {
        "id": "uboot_004",
        "category": "UBOOT",
        "plaintext": "BRENNSTOFFVORRATNURNOXFUERFUENFTAGEREICHENDXERBITTEDRINGENDVERSORGUNGSTREFFENX",
        "context": "Emergency supply request from a U-boat running low on fuel.",
    },
    {
        "id": "uboot_005",
        "category": "UBOOT",
        "plaintext": "MUSSTAUQENWEGENFEINDLIQERORTUNGXWASSERBOMBENANGRIFFDREISTUNDENXKEINESCHAEDENX",
        "context": "U-boat report after being forced to dive due to depth charge attack.",
    },
    {
        "id": "uboot_006",
        "category": "UBOOT",
        "plaintext": "RUFZEIQLANGXVBOOTVIERDREIAQTVONKIELAUSGELAUFENXZIELQUADRATDORAVIERSIEBENZWEIX",
        "context": "U-boat departure notification from Kiel naval base to BdU operations room.",
    },
    {
        "id": "uboot_007",
        "category": "UBOOT",
        "plaintext": "GELEITDIENSTFUERVBOOTREMUSXABFAHRTWAERNEMUENDEXSEXZEHNUHRXMITSIEBENWEITERENVBOOTEN",
        "context": "Convoy escort notification for U-boat group departing Warnemünde.",
    },
    {
        "id": "uboot_008",
        "category": "UBOOT",
        "plaintext": "FEINDLIQERZERSOERERGESIQTETXQUADRATADASECHSEINSXHOEQSTEGESCHWINDIGKEITFAHRENX",
        "context": "Enemy destroyer sighting report, U-boat attempting to evade.",
    },
    {
        "id": "uboot_009",
        "category": "UBOOT",
        "plaintext": "WETTERKURZSIGNALXLUFTDRUQNEUNSIEBENNEUNMILLIBARXWINDWESTFUENFXSEEGANGLEIQQX",
        "context": "Compressed weather short signal (Wetterkurzschlüssel) from U-boat at sea.",
    },
    {
        "id": "uboot_010",
        "category": "UBOOT",
        "plaintext": "ERFOLGSBERIQTXZWEIHANDELSSCHIFFEVERSENKTXGESAMTZWOELFEINHALBTAUSENDTONNENX",
        "context": "U-boat success report claiming two merchant ships sunk.",
    },
    {
        "id": "uboot_011",
        "category": "UBOOT",
        "plaintext": "VONBEFEHLSHABERDERUBOOTEANALLEVBOOTEATLANTIKXNEUEOPERATIONSZONEQUADRATEDORAFINKENX",
        "context": "BdU broadcast to all Atlantic U-boats assigning new patrol zones.",
    },
    {
        "id": "uboot_012",
        "category": "UBOOT",
        "plaintext": "VBOOTSEQSEINSNULLXSQWERBESQAEDIGTXRUEKFAHRTNAQBRESTXERBITTEGELEITSQUTZX",
        "context": "Damaged U-boat requesting escort for return to Brest naval base.",
    },

    # --- OPERATIONAL ORDERS (12) ---
    {
        "id": "befehl_001",
        "category": "BEFEHL",
        "plaintext": "BEFEHLNUMMERDREIVIERSIEBENXALLEEINHEITENVORRUEQKENRIQTUNGNORDOSTXBEREITAQAFTBISNEUNZEHNUHRDREISSIGX",
        "context": "Divisional order intercepted from Army Group North, directing advance northeast.",
    },
    {
        "id": "befehl_002",
        "category": "BEFEHL",
        "plaintext": "ANGRIFFAUFLINIEALFABERTAZWEINULLDREIUHRXSQWERARTILLERIEVORBEREITUNGABEINSAQTZEHNUHRX",
        "context": "Attack order specifying artillery preparation timeline.",
    },
    {
        "id": "befehl_003",
        "category": "BEFEHL",
        "plaintext": "SOFORTIGERABRUQNAQWESTENXFEINDLIQEDURQBRUQSSTELLUNGCAESARXALLEEINHEITENZURUEKNEHMEX",
        "context": "Emergency withdrawal order after enemy breakthrough.",
    },
    {
        "id": "befehl_004",
        "category": "BEFEHL",
        "plaintext": "FUENFTEPANZERDIVISIONVERLEGTNAQSEKTORSUEDXANKUNFTERWARTETSIEBENUHRDREISSIGX",
        "context": "Panzer division transfer order, intercepted from Army Group South.",
    },
    {
        "id": "befehl_005",
        "category": "BEFEHL",
        "plaintext": "FLIEGERKOPSZWEIXALLEBOMBERGRUPPENSTARTENZIELHAFENANLAGENXNULLDREIHUNDERTXHOEQSTEALARMSTUFE",
        "context": "Luftwaffe bombing mission order targeting harbor installations.",
    },
    {
        "id": "befehl_006",
        "category": "BEFEHL",
        "plaintext": "VERTEIDIGUNGSBEFEHLXHAUPTSTELLUNGISTUMJEDENPREISZUHALTENXKEINWEITERERRUQZUGX",
        "context": "Defensive order to hold position at all costs, no further retreat authorized.",
    },
    {
        "id": "befehl_007",
        "category": "BEFEHL",
        "plaintext": "AUFKLAERUNGSBEFEHLXDRITTEKOMPANIEERKUNDETSTRASSENNAQNORDENXERGEBNISMELDENBISVIERZEHNUHR",
        "context": "Reconnaissance order directing 3rd Company to scout roads to the north.",
    },
    {
        "id": "befehl_008",
        "category": "BEFEHL",
        "plaintext": "PIONIERKOMPANIESOLLBRUEQEUEBERFLUSSSPREEHERSTELLENXFERTIGSTELLUNGBISHEUDNAQTX",
        "context": "Pioneer company ordered to construct bridge over the Spree river.",
    },
    {
        "id": "befehl_009",
        "category": "BEFEHL",
        "plaintext": "NEUEKOMANDOSTRUKTURXOBERSTVONSTEINNXUEBERNIMMTFUEHRUNGDERABSQNITTSNORDX",
        "context": "Command restructuring notification, new sector commander appointed.",
    },
    {
        "id": "befehl_010",
        "category": "BEFEHL",
        "plaintext": "ALLENAQRIQTENEINHEITENXFUNKSTILLEXNURNOTFUNKVONNULLEINSUHRBISMITTTERNAQTX",
        "context": "Radio silence order to all signals units ahead of major operation.",
    },
    {
        "id": "befehl_011",
        "category": "BEFEHL",
        "plaintext": "GEHEIMXOBERESKOMMANDODERWEQRMAQTXOPERATIONSPLANFAELLTWINTERXAUSFUEHRUNGAMDRITTENDEZEMBERX",
        "context": "Top secret OKW operation plan intercepted, specifying execution date.",
    },
    {
        "id": "befehl_012",
        "category": "BEFEHL",
        "plaintext": "NAQRIQTENVERBINDUNGNAQSEKTOROSTUNTERBROQENXFUNKVERBINDUNGWIEDERHERSTELLENPRIORX",
        "context": "Order to restore communications link with eastern sector.",
    },

    # --- STATUS REPORTS (12) ---
    {
        "id": "lage_001",
        "category": "LAGEBERICHT",
        "plaintext": "LAGEBERIQTXMUNITIONSVORRATGUTXVERPFLEGUNGFUERFUENFTAGEGESIQERTXPERSONALSTAERKEDREIHUNDERTFUENFX",
        "context": "Routine status report from a battalion on the Eastern Front.",
    },
    {
        "id": "lage_002",
        "category": "LAGEBERICHT",
        "plaintext": "KEINEBESONDERENEREIGNISSEZUMELDENZZMELDUNGABGESQLOSSENXHEILHITLERX",
        "context": "Standard 'nothing to report' message, common crib for Bletchley Park.",
    },
    {
        "id": "lage_003",
        "category": "LAGEBERICHT",
        "plaintext": "TAEGLIQERBERIQTXFEINDLIQEAKTIVITAETGERINGXEIGENESTELLUNGENUNVERAENDERTGEHALTEX",
        "context": "Daily situation report from a quiet sector, minimal enemy activity.",
    },
    {
        "id": "lage_004",
        "category": "LAGEBERICHT",
        "plaintext": "VERLUSTMELDUNGXDREITOTEZWANZIGVERWUNDETESIEBENVERMISSXSQWEREVERLUSTEINDRITTERKOMPANIEX",
        "context": "Casualty report intercepted from regiment headquarters.",
    },
    {
        "id": "lage_005",
        "category": "LAGEBERICHT",
        "plaintext": "VERSORGUNGSLAGEKRITISQXBRENNSTOFFVORRATNURFUERZWEITAGEXDRINGENDNAQSQUBERFOERDERNX",
        "context": "Critical supply situation report, requesting urgent resupply.",
    },
    {
        "id": "lage_006",
        "category": "LAGEBERICHT",
        "plaintext": "PANZERSTAERKEBEREIQTXVIERZEHNPANZERKAMPFWAGENEINSNOXEINSATZBEREITXAQUZERSOERERAUSGEFALLX",
        "context": "Armored strength report from a Panzer regiment.",
    },
    {
        "id": "lage_007",
        "category": "LAGEBERICHT",
        "plaintext": "TAETIGKEITSBERIQTLUFTFLOTTEZWEIXEINSAETZEZWEIUNDVIERZIGFLIEGERSTAFFELNHEUTEX",
        "context": "Luftflotte 2 activity report listing sorties flown.",
    },
    {
        "id": "lage_008",
        "category": "LAGEBERICHT",
        "plaintext": "FEINDLAGEBERIQTXFEINDVERSTAERKTSTELLUNGENMITPANZERNUNDINAFNTERIEXANGRIFFERWARTEX",
        "context": "Enemy situation assessment reporting reinforcements.",
    },
    {
        "id": "lage_009",
        "category": "LAGEBERICHT",
        "plaintext": "BEFESTIGUNGSARBEITENAMHAUPTSTELLUNGABGESQLSSENXDRAHTHINDERNISSEUNDMINENFELDERVOLLSTAENDG",
        "context": "Fortification completion report, defensive preparations finished.",
    },
    {
        "id": "lage_010",
        "category": "LAGEBERICHT",
        "plaintext": "NAQRIQTENMELDUNGXFEINDLIQERFUNKVERKEHRSTARKANGESTIEGENXMOEGLIQUERWEISEANGRIFFSGRUPPENX",
        "context": "Signals intelligence report noting increased enemy radio traffic.",
    },
    {
        "id": "lage_011",
        "category": "LAGEBERICHT",
        "plaintext": "SANITAETSBERIQTXKRANKENSTANDEINSZWOSIEBENGEINXEPIDEMIEUNTERKONTROXLAZARETTAUSGELASTETX",
        "context": "Medical status report, epidemic under control but hospitals at capacity.",
    },
    {
        "id": "lage_012",
        "category": "LAGEBERICHT",
        "plaintext": "GEFEQTSBERIQTXFEINDLIQERANGRIFFABGEWIESENXEIGENEVERLUSTEGERINGXSTELLUNGENGEHALTEX",
        "context": "Combat report: enemy attack repelled, positions held.",
    },

    # --- MISCELLANEOUS (12) ---
    {
        "id": "misc_001",
        "category": "MISC",
        "plaintext": "ANERKENUNGANDIEMAQNNSCHAFTENFUERTAPFEREXVERTEIDIGUNGAMBRUEQKENKOPFXHEILHITLERX",
        "context": "Commendation message for troops defending a bridgehead.",
    },
    {
        "id": "misc_002",
        "category": "MISC",
        "plaintext": "AGENTMELDETFEINDLIQETRUPPENBEWEGUNGENSUELIQQVONPARISINRIQTUNGDIJONXSTAERKEUBEKANTX",
        "context": "Intelligence report from agent behind enemy lines.",
    },
    {
        "id": "misc_003",
        "category": "MISC",
        "plaintext": "TESTFUNKMELDUNGXFUNKANLAGEGEPRUEFTUNDBEREITXSENDEQUALITAETGUTXEMPFANGKLARX",
        "context": "Radio test message (Abstimmspruch) — common crib target for codebreakers.",
    },
    {
        "id": "misc_004",
        "category": "MISC",
        "plaintext": "URLAUBSANTRAGEGENEHMIGTFUEROFFIZIEREVONDERDRITTENBRIGADEXABREISEAMSIEBTENX",
        "context": "Leave approval notice for officers — routine administrative message.",
    },
    {
        "id": "misc_005",
        "category": "MISC",
        "plaintext": "NAQSQUBLIEFERUNGXZWOELFWAGENLADUNGENMUNITIONERREIQENVORRATSLAGERSIEBENHUNERTTX",
        "context": "Supply delivery notification, ammunition shipment.",
    },
    {
        "id": "misc_006",
        "category": "MISC",
        "plaintext": "EINSSIEBENDREINULLVBOOTXERGIBTSIQDEMFEINDNIQTXSIEGEODERTODXHEILHITLERX",
        "context": "Defiant U-boat message, common propaganda-style communication.",
    },
    {
        "id": "misc_007",
        "category": "MISC",
        "plaintext": "ABFANGMELDEUNGXFEINDLIQEBOMBERVERBAENDEIMANZUGAQSEVOMWESTENXALLEJAEGERSTAFFELNSTARTX",
        "context": "Air defense interception alert, enemy bomber formations approaching.",
    },
    {
        "id": "misc_008",
        "category": "MISC",
        "plaintext": "GEHEIMHALTUNGSSTUFEXXSTRENGGEHEIMXXNURFUERFUEHRUNGSOFFIZIEREXKEINEFUNKUEBERTRAGUNGX",
        "context": "Classification notice: top secret, officers only, no radio transmission.",
    },
    {
        "id": "misc_009",
        "category": "MISC",
        "plaintext": "KRIEGSTAGEBAQEINTRAGXHEUTIGERDATENULLAQTMAERZVIERUNDVIERZIGXLAGEUNVERAENDERTX",
        "context": "War diary entry, March 8, 1944 — routine daily log.",
    },
    {
        "id": "misc_010",
        "category": "MISC",
        "plaintext": "MELDUNGFUERGENERALSTABDESEERESXFEINDLIQEPANZERVERBAENDEDUQBRUQBEIKURSXZWEITEDIVISIONXXX",
        "context": "Urgent report to Army General Staff regarding enemy armored breakthrough.",
    },
    {
        "id": "misc_011",
        "category": "MISC",
        "plaintext": "EISENBAHNVERSORGUNGXNAQSQUBTRANSPORTUEBERSTUTTGARTHAUPBAHNHOFNAQDRESDENXANKUNFTMORGENX",
        "context": "Railway supply logistics message, transport routing notification.",
    },
    {
        "id": "misc_012",
        "category": "MISC",
        "plaintext": "SONDERMELDUNGXDERADLERHORSTISTEINGENNOMENXZIELDESANGRIFFSSERREIQTXHEIMKEHRENDEX",
        "context": "Special bulletin: the Eagle's Nest has been taken, objective achieved.",
    },
]


# ---------------------------------------------------------------------------
# Machine configurations per difficulty tier
# ---------------------------------------------------------------------------

def _generate_settings(difficulty: str, rng: random.Random) -> dict:
    """Generate Enigma machine settings appropriate for difficulty tier."""
    rotors = ["I", "II", "III", "IV", "V"]
    reflectors = ["UKW-A", "UKW-B", "UKW-C"]

    # Select 3 random rotors (no duplicates)
    rotor_order = rng.sample(rotors, 3)
    reflector = rng.choice(reflectors)

    # Ring settings: 1-26
    ring_settings = [rng.randint(1, 26) for _ in range(3)]

    # Initial positions: 1-26
    initial_positions = [rng.randint(1, 26) for _ in range(3)]

    # Plugboard pairs
    if difficulty == "easy":
        num_pairs = rng.randint(6, 10)
    elif difficulty == "medium":
        num_pairs = rng.randint(3, 5)
    else:  # hard
        num_pairs = rng.randint(2, 3)

    available = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    rng.shuffle(available)
    plugboard = []
    for i in range(0, num_pairs * 2, 2):
        if i + 1 < len(available):
            plugboard.append((available[i], available[i + 1]))

    return {
        "rotor_order": rotor_order,
        "ring_settings": ring_settings,
        "initial_positions": initial_positions,
        "reflector": reflector,
        "plugboard": plugboard,
    }


def _generate_cribs(plaintext: str, difficulty: str, rng: random.Random) -> list[dict]:
    """Generate known-plaintext cribs from a message."""
    cribs = []
    msg_len = len(plaintext)

    if difficulty == "easy":
        # 1-2 short cribs
        num_cribs = rng.randint(1, 2)
        crib_len_range = (4, 8)
    elif difficulty == "medium":
        # 2-3 medium cribs
        num_cribs = rng.randint(2, 3)
        crib_len_range = (5, 12)
    else:  # hard
        # 3-4 longer cribs
        num_cribs = rng.randint(3, 4)
        crib_len_range = (6, 15)

    used_ranges = []
    for _ in range(num_cribs):
        crib_len = rng.randint(*crib_len_range)
        crib_len = min(crib_len, msg_len - 1)

        # Try to find a non-overlapping position
        for _attempt in range(50):
            pos = rng.randint(0, msg_len - crib_len)
            # Check no overlap with existing cribs
            overlap = False
            for start, end in used_ranges:
                if not (pos + crib_len <= start or pos >= end):
                    overlap = True
                    break
            if not overlap:
                crib_text = plaintext[pos:pos + crib_len]
                cribs.append({"text": crib_text, "position": pos})
                used_ranges.append((pos, pos + crib_len))
                break

    return cribs


def _revealed_info(settings: dict, difficulty: str) -> dict:
    """Determine what machine settings to reveal based on difficulty."""
    if difficulty == "easy":
        # Reveal everything except initial positions
        return {
            "rotor_order": settings["rotor_order"],
            "ring_settings": settings["ring_settings"],
            "reflector": settings["reflector"],
            "plugboard": [list(p) for p in settings["plugboard"]],
            "hidden": ["initial_positions"],
        }
    elif difficulty == "medium":
        # Reveal rotor order and reflector only
        return {
            "rotor_order": settings["rotor_order"],
            "reflector": settings["reflector"],
            "num_plugboard_pairs": len(settings["plugboard"]),
            "hidden": ["ring_settings", "initial_positions", "plugboard"],
        }
    else:  # hard
        # Reveal only reflector (or choice of 2)
        return {
            "reflector": settings["reflector"],
            "num_plugboard_pairs": len(settings["plugboard"]),
            "hidden": ["rotor_order", "ring_settings", "initial_positions", "plugboard"],
        }


# ---------------------------------------------------------------------------
# Build all tasks
# ---------------------------------------------------------------------------

def build_all_tasks() -> dict[str, dict]:
    """Build and encrypt all tasks, returning a dict keyed by task ID."""
    # Deterministic RNG for reproducibility
    rng = random.Random(42)

    # Assign splits and difficulties
    # train: 15 easy, 15 medium, 10 hard = 40 tasks
    # test:  5 easy, 10 medium, 5 hard = 20 tasks
    assignments = []

    # Shuffle messages
    msg_indices = list(range(len(MESSAGES)))
    rng.shuffle(msg_indices)

    # Assign difficulties and splits
    train_easy = msg_indices[:15]
    train_medium = msg_indices[15:30]
    train_hard = msg_indices[30:40]
    test_easy = msg_indices[40:45]
    test_medium = msg_indices[45:55]
    test_hard = msg_indices[55:60]

    plan = []
    for idx in train_easy:
        plan.append((idx, "train", "easy"))
    for idx in train_medium:
        plan.append((idx, "train", "medium"))
    for idx in train_hard:
        plan.append((idx, "train", "hard"))
    for idx in test_easy:
        plan.append((idx, "test", "easy"))
    for idx in test_medium:
        plan.append((idx, "test", "medium"))
    for idx in test_hard:
        plan.append((idx, "test", "hard"))

    tasks = {}
    for msg_idx, split, difficulty in plan:
        msg = MESSAGES[msg_idx]
        task_id = f"{msg['id']}_{difficulty}"

        # Generate machine settings
        settings = _generate_settings(difficulty, rng)

        # Encrypt the plaintext
        machine = EnigmaMachine(
            rotor_order=settings["rotor_order"],
            ring_settings=settings["ring_settings"],
            initial_positions=settings["initial_positions"],
            reflector=settings["reflector"],
            plugboard=settings["plugboard"],
        )
        ciphertext = machine.encrypt(msg["plaintext"])

        # Verify round-trip immediately
        machine.reset()
        decrypted = machine.encrypt(ciphertext)
        assert decrypted == msg["plaintext"].upper().replace(" ", ""), (
            f"Round-trip failed for {task_id}: "
            f"expected {msg['plaintext']}, got {decrypted}"
        )

        # Generate cribs
        cribs = _generate_cribs(msg["plaintext"], difficulty, rng)

        # Generate revealed info
        revealed = _revealed_info(settings, difficulty)

        # Format ciphertext in 5-letter groups for display
        ciphertext_grouped = " ".join(
            ciphertext[i:i + 5] for i in range(0, len(ciphertext), 5)
        )

        tasks[task_id] = {
            "id": task_id,
            "split": split,
            "difficulty": difficulty,
            "category": msg["category"],
            "plaintext": msg["plaintext"],
            "ciphertext": ciphertext,
            "ciphertext_grouped": ciphertext_grouped,
            "rotor_order": settings["rotor_order"],
            "ring_settings": settings["ring_settings"],
            "initial_positions": settings["initial_positions"],
            "reflector": settings["reflector"],
            "plugboard": [list(p) for p in settings["plugboard"]],
            "revealed_info": revealed,
            "cribs": cribs,
            "context": msg["context"],
        }

    return tasks


# Build tasks at module load time
ALL_TASKS = build_all_tasks()
ALL_SPLITS = ["train", "test"]


def get_task_counts() -> dict:
    """Get task counts by split and difficulty."""
    counts: dict[str, dict[str, int]] = {}
    for task in ALL_TASKS.values():
        split = task["split"]
        diff = task["difficulty"]
        if split not in counts:
            counts[split] = {}
        counts[split][diff] = counts[split].get(diff, 0) + 1
    return counts
