# drift

drift is a space trading and combat game for ospab.os. You fly a small courier ship between the
star systems of eight generated galaxies, trade, fight, and follow a seven-chapter story that
ends. It is written for this system and is not a port of anything. Copyright (c) 2026 ospab,
AGPL-3.0-only.

The game draws everything itself with a software 3D renderer: z-buffered solid ships with flat
and Gouraud shading, procedural planets with a day/night terminator and atmosphere, stars, a
nebula sky, particle explosions, glowing laser bolts and a cheap bloom pass. Sound is generated, see below.

## Install and run

```
# tomato -U drift-0.1.0.tmt
# drift            native interface size
# drift -r 2       draw the interface at half the screen size (less memory, faster)
```

Needs: the framebuffer and raw keyboard calls (see [System call ABI](syscall-abi.md), "Screen,
keyboard, clock"), a user heap of about 32 MiB for the 1080p default (`HEAP_SIZE` in
`user/liboos/src/heap.rs`; the program prints a clear message and exits if the heap is too small),
and under 1 MB of disk for the package. Run it from the console, not over ssh or serial: it takes
over the screen and the keyboard until you quit it. Ctrl+C always kills it.

Commanders and settings are stored as small files (`drift-slotN.sav`, `drift.cfg`) in `/home`,
or in `/tmp` if `/home` cannot be written.

## The tutorial

New Game offers a tutorial after the intro; the main menu also has a Tutorial item that runs it
as a practice flight (nothing is saved). It is an interactive flight school of 13 steps, shown in
a panel with the exact keys as key caps and a checklist of finished steps: launch, steer, throttle,
rear and side views, the dashboard (the panel is highlighted and every instrument is named), the
compass, locking a training drone, firing at it, flying to a beacon, the in-system jump (you are
moved into open space first), docking by hand with a guide, trading one cargo and buying fuel.
Each step waits for you to do it. X skips the tutorial at any moment. The tutorial lends you a
docking computer (press D at the dock step) and returns it at the end. While you are close to a
station the docking guide shows where to steer: a path marker for the nose, the roll to apply and
your speed against the 150 m/s limit.

## The story

You inherit the Tern runabout *Moth Lark* from your aunt Halda Venn, a courier who vanished near
an uncharted pocket of the drift. The drift is the layer of broken distance ships use to jump. The
Vael live in it. The Cinder Syndicate has been cutting the anchors that keep the drift's pockets
closed, and every cut makes the Vael more dangerous.

| Chapter | Name | You need | What you do |
|---|---|---|---|
| 1 | First Light | nothing, starts at once | Launch, fly to the beacon, dock. Teaches the controls. |
| 2 | The Sealed Ledger | nothing | Carry a sealed ledger to the broker Tobias Quill. Raiders may track it. |
| 3 | Wreck of the Small Hours | nothing | Recover three cargo canisters from Halda's first ship (needs a fuel scoop or salvage tether), return to Quill. |
| 4 | Cinder Captain | 8 kills | Destroy the raider captain Dann Corvane, report to Quill. |
| 5 | The Envoy | 2500 credits | Hold station near a Vael needle until it answers the Venn Key, survive the ambush, report. |
| 6 | Anchor Run | 24 kills | Destroy five raiders cutting an anchor, report. |
| 7 | The Cinder Sovereign | 64 kills | Destroy Director Marrow's flagship at the Mother Anchor. |

Chapters 2 to 7 are accepted on the contracts board (F11). Between chapters you are free to trade,
hunt pirates, mine and explore; the kill and credit requirements are what the free play builds
towards. The story is bound to the first galaxy. Destroying the Sovereign starts the ending
(text over a camera scene), then the credits, then the question "Continue in free play?". Either
answer saves the commander into its slot, marked as completed.

If the ship is destroyed and you have no escape capsule, the game over screen shows your totals
and offers to load the last save or return to the menu.

## Keys

Flight:

| Key | Action |
|---|---|
| Left / Right | roll |
| Up / Down | pitch (Down climbs; invert in Settings) |
| A / Z | throttle up / down |
| Space | fire the laser mounted on the current view |
| T / Y | lock the target nearest the view axis / clear the lock |
| M | fire a missile (the lock takes one second) |
| C | release chaff (needs a countermeasure pod) |
| J (hold) | in-system jump, blocked by mass lock |
| H | hyperspace to the destination chosen on a chart |
| G | galactic drive (one use) |
| D | docking computer on/off (any roll or pitch key turns it off) |
| E | eject in the escape capsule |
| P or Esc | pause menu |
| Tab | key map and dashboard legend (Left/Right switches the page) |

Screens: F1 front view (launch when docked), F2 rear, F3 left, F4 right, F5 status, F6 galactic
chart, F7 local chart, F8 system data, F9 market, F10 equipment, F11 contracts, F12 save. F9 to
F12 work only when docked. On charts the arrows jump to the neighbouring system, Enter sets the
destination, Home returns to your system. In the market B or Enter buys, S sells, Shift makes it
ten at a time or everything. In equipment Enter buys, Del removes a laser (half price back).

Menus use the arrow keys, Enter and Esc. The mouse is not used. Every screen lays itself out from
the real framebuffer size (a scale derived from a 960 by 540 design), so 800x600 up to 2560x1440
work; the host harness checks every screen at eight resolutions in both languages for text that
leaves the screen or overlaps other text.

## Sound

All sound is generated at run time (no sample files): oscillators, noise, envelopes and filters
mixed to 48 kHz stereo. There is an engine hum that follows the throttle, the jump drive and the
hyperspace charge, laser and enemy shots, shield and hull hits, explosions, missile launches, lock
beeps, scooping, chaff, docking clamps, menu clicks, alarms for low energy, a hot cabin and
incoming missiles, and a calm ambient pad with sparse bell notes on the title screen, in menus and
while docked. Sounds are panned by their direction relative to your nose and fade with distance.
Master, effects and music volume are in Settings (0 to 10). The program feeds the sound device
every frame and stays silent if the device cannot be opened.

## Dashboard

The bottom panel names every bar and shows its value: Shield fwd and Shield aft, Energy (the hull,
in four banks), Fuel in light years, Cabin temp, Laser temp (of the laser on the current view),
Altitude above the planet, Speed in m/s, Throttle, Roll, Pitch, Missiles. Bars turn amber and then
red when a resource is low or something is hot. The scanner shows contacts with a stick for height;
the compass above it points to the station (ST) or planet (PL), a filled dot meaning ahead.

## Settings

Language (English or Russian, saved with the settings), invert pitch, bloom on/off, retro wireframe mode (flat green wireframes instead of solid
shading), and the 3D resolution (low, medium, high; the scene is rendered at 0.34, 0.5 or 0.75 of
the interface size and scaled up, the HUD is always drawn at full size). If the average frame
takes longer than 38 ms the program lowers the 3D resolution on its own for that run.

## Universe and markets

The universe is generated from fixed seeds: 8 galaxies of 256 systems. Each system has a name
from a syllable generator, a government (8 kinds, law level 0 to 7), an economy (8 kinds), a tech
level 1 to 14, population, product, a planet type and star colour, and a one-line description.
Names are unique within a galaxy. The galactic chart shows the whole galaxy, the local chart the
neighbourhood with names. The jump range is 7 light years and each tenth of a light year costs
one tenth of fuel.

There are 16 commodities. A system's economy makes some of them cheap and plentiful (it produces
them) and others dear and scarce (it consumes them). Tech level gates which advanced goods are
made at all. Prices also carry a fixed regional bias and a short-term fluctuation that changes
each time you arrive. Buying raises the price, selling lowers it, and you sell at 92 percent of
the buy price (98 in trade hubs). Three goods are illegal: Dreamfog, Ghost Cores and Warhead
Casings. They sell for more where the law is strict and may be missing from the market there.
Every unit takes one slot of the hold; the base hold is 20.

## Ship and equipment

The Tern has fore and aft shields (100 each), four energy banks (the hull), four missile racks
and a laser mount on each side (front, rear, left, right); only the front mount is fitted at the
start. Equipment is limited by the tech level of the station:

| Item | Tech | Effect |
|---|---|---|
| Pulse, Beam, Military, Mining laser | 1, 5, 9, 3 | one per mount; heat limits the rate of fire |
| Hold extension (two levels) | 3, 7 | +15 hold slots each |
| Missiles | 2 | up to 4, homing, one-second lock |
| Countermeasure pod | 3 | chaff kills most missiles aimed at you |
| Fuel scoop | 4 | skim a star for fuel, scoop canisters |
| Escape capsule | 4 | survive the loss of the ship |
| Shield booster | 5 | shields 150 |
| Heat sink | 5 | lasers cool twice as fast |
| Docking computer | 6 | flies the approach and the slot |
| Salvage tether | 6 | pulls canisters in from 900 m |
| Energy unit | 7 | faster energy and shield recharge |
| Ghost plate | 8 | cuts the chance that customs finds illegal cargo to a third |
| Galactic drive | 10 | one jump to the next galaxy |

Hits that get past the shields can damage a random system. Damaged equipment does not work until
you pay for repairs at a station.

## Flying and fighting

*Docking.* The station is a rotating drum. Its slot turns with it. Fly nose first at the slot
with your wings level with the slot (either way up), slower than 150 m/s. The wing tips must clear
the slot edges at the moment you cross the plane; if not, you crash into the frame and take
damage. The docking computer does the same automatically.

*Jumps.* J starts an in-system jump (up to 9000 m/s) that stops by itself near the planet, the
star, the station or other ships (mass lock). H starts a four-second hyperspace countdown if a
destination is chosen, you are not mass locked and have the fuel.

*Drift ambush.* A jump can drop you into a drift pocket with several Vael ships and no planet or
station. Press H to re-enter; this costs no fuel. Systems with weak law have more ambushes.

*Star skimming.* Close to a star with a fuel scoop, fuel comes in and the cabin heats up. Above 90
percent the cabin drains energy; inside the star you die. Cabin and laser temperatures are on the
instrument panel.

*Enemies.* Pirates attack traders and, if you carry anything worth taking, you. Police patrol near
the station and attack pirates and aliens, and you if your legal record is bad. Bounty hunters
come for fugitives. The Vael attack on sight. Ships flee when badly hurt, use missiles and chaff,
and drop cargo canisters and escape capsules. Pirates and aliens pay a bounty for each kill.
Rocks can be broken up with any laser; a mining laser is much faster and the rocks drop ore.

*Legal status.* Clean below 10, offender from 10, fugitive from 50. Shooting traders, killing
traders or police, firing at the station and being caught with illegal cargo add to it. It decays
slowly over time and by 3 per jump. Docking as a fugitive costs a fine and lowers the record to
a warning; customs may also confiscate illegal cargo and fine you.

*Ranks.* By kills: Stray, Drifter (4), Picket (16), Lancer (48), Striker (128), Reaver (320),
Warhawk (800), Sentinel (2000), Paragon (5000), Apex (12000).

## Contracts

Besides the story, every station offers a parcel run (carry a sealed package to another system,
raiders may track you) and a wanted pirate (destroy a captain in another system, report back).
You can hold two at a time.

## Saving

F12 when docked, five slots. The menu offers Continue (the most recently played slot) and Load.
Saves are 256-byte files with a checksum; a damaged or foreign file is ignored.

## Source and tests

`apps/drift-core` is the game: simulation, renderer, menus and story, all `no_std` with `alloc`,
its own sin, cos and sqrt, no floating point library, and a fixed 30 Hz simulation step (the
frame rate only affects drawing). It draws into a plain 0x00RRGGBB pixel buffer and takes input as
abstract actions. `apps/drift` is the ring 3 front end: framebuffer, raw scancodes, frame pacing,
files. Build the package like any other (`apps/build.sh`, which packs `apps/pkg/drift.toml`).

The core builds and tests on the host. The harness in `apps/drift-core/tests/harness.rs` plays
scripted input (menus, launch, beacon, docking computer, trading, combat, bounty, legal status,
missiles, hyperspace, saving, death, ending) and writes screenshots as PPM files:

```
cargo +nightly test --manifest-path apps/drift-core/Cargo.toml --target x86_64-pc-windows-msvc --release -- --nocapture
```

Run it from the repository root: the ring 3 target in `apps/.cargo/config.toml` applies only to
cargo runs started inside `apps/`, and `--target` overrides the kernel target of the root
configuration. Screenshots are written to the directory in the environment variable
`DRIFT_SHOTS` (default `apps/drift-core/target/drift-shots` when run from the crate directory).

## Known limits

- No mouse. Sound needs the audio device of the system (silent without it).
- Russian is complete for all interface text, story, tutorial and generated system descriptions;
  generated system names stay in Latin letters. The font is the game's own 8x8 bitmap set with
  original Cyrillic glyphs, so text is UTF-8 and monospaced.
- The commander is saved only when docked, and a loaded game starts docked.
- The story lives in the first galaxy; using the galactic drive leaves it behind.
- Heap: the stock liboos heap of 4 MiB is too small; see the install section.
