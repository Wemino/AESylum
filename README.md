# AESylum

A tool to remove the legacy DRM from *Alice: Madness Returns*.

## Disclaimer

The goal of this project is not to enable piracy. Pirated copies have existed for over a decade and none of them went through the trouble of defeating MFortress. The DRM only ever ran on legitimate, purchased builds. What this project does is preserve a specific version of the game that would otherwise quietly disappear. AESylum only works on builds that are no longer sold.

## What this is for

There are three PC builds of *Alice: Madness Returns* that shipped:

- An **April 7th 2011** CD build with SecuROM. Not worth touching.
- An **April 18th 2011** build with only a light store wrapper on top. SteamStub on the Steam version, something comparable on the EA App version. Neither layer has anti-tamper, runtime hashing, or anything invasive. This is the build currently sold on both stores.
- A **May 10th 2011** build, which shipped with a custom anti-tamper DRM called **MFortress**. This build was sold up until 2016 when it was pulled from Steam, then brought back on January 14th 2022. The 2022 re-release silently swapped in the older April build instead.

AESylum targets the May build. The other two aren't supported and aren't the point of the project; the April build already runs without any help.

The May build is the one worth preserving. It has:

- Native implementation of the "Weapons of Madness" DLC.
- More command-line parameters.
- Correct chapter cinematic names in the Extras menu. The April build has several wrong.
- Likely various bug fixes and optimizations that went in during the extra three weeks of development.

My guess is that EA lost the source code, or at least lost any clean build of the May version (if those ever existed). Otherwise there'd be no reason to sell the older April build in 2022 rather than a May build without MFortress attached.

This might also explain why *Alice: Madness Returns – The Complete Edition* isn't sold anymore on PC. It bundled the first *American McGee's Alice* and the Weapons of Madness DLC, and that DLC doesn't work on the April build. Pulling the bundle is a lot easier than fixing it. Just a theory.

I also needed MFortress gone to run [MadnessPatch](https://github.com/Wemino/MadnessPatch), a runtime code-patching mod I wrote for the game. The anti-tamper trips the moment anything touches the code, so the mod is unusable on the May build until the DRM is removed. That's the reason this project exists.

## What it does

1. Strips the Steam wrapper if present. The EA build doesn't have this layer.
2. Decrypts the encrypted code sections. In a legitimate run this is done by `awc.dll` after it validates the license. AESylum does it directly with the same AES routine.
3. Rewrites the PE header to skip the DRM entry point. The original entry point runs a setup routine that installs inline hooks on `kernel32!CreateThread` and `ntdll!NtContinue`, sets hardware breakpoints on every thread the game spawns, and loads `awc.dll` to handle licensing, decryption, and import resolution. AESylum takes over the import resolution that `awc.dll` would have done at runtime, and repoints the entry point at the real game OEP. With the DRM entry point skipped, `awc.dll` no longer needs to be loaded.
4. Applies thousands of patches across the binary:
   - Every hash check that compares a computed value against a baked-in expected hash.
   - Every anti-debug check, including the RDTSC timing checks scattered through game routines.
   - Every call into `awc.dll`'s session license validator, which the game invokes periodically during gameplay to re-check whether the license is still valid.
   - The hashing loops themselves, skipped entirely to save the time they'd waste and to avoid reading regions of `awc.dll` that the loops expect to be mapped. Since the DRM entry point no longer runs, `awc.dll` isn't loaded, and anything that tried to hash through it would fault.

The result is a completely standalone, clean executable that behaves like an unlocked May build would have if EA had ever shipped one.

## About MFortress

MFortress is a custom DRM apparently built by or for EA, wrapped around `awc.dll`, an EACore component responsible for licensing, decryption, and import resolution. The anti-tamper and anti-debug work is MFortress itself. `awc.dll` is what it's protecting, and what the game calls into for anything license-related. *Alice: Madness Returns* might be the only game that shipped with this layer. I haven't found another title with the same signatures, and there's essentially zero public writing about it.

The checks protect each other. Each hash check covers a region of code that contains other hash checks, so removing any single one trips a different one that was watching it. The only way through is to neutralize all of them in one pass. They're also integrated into normal control flow rather than living in a separate supervisor thread, which means a sloppy patch can silently corrupt game state hours later without an obvious failure.

The hashing is a parameterized framework rather than a single algorithm. There are 2,000+ individual check instances scattered through the code, each scanning some region of the binary. Collectively they cover the whole thing, with heavy overlap so every region is watched by more than one check. Each instance mixes and matches between a few different loop body styles (an FNV-1a variant with custom primes, a djb2-style multiply-accumulate, a shift-xor nibble-rotate, and a backward-scan variant), then runs the result through one of a few finalizer variants before the comparison.

The binary is also riddled with anti-disassembly tricks. These don't affect runtime behavior and AESylum doesn't patch them. Their only purpose is to waste the time of anyone trying to statically analyze the binary.

## Supported builds

- Steam build, TimeDateStamp `0x4DC8887C`
- EA store build, TimeDateStamp `0x4DC89913`

Both were compiled on May 10th 2011. The EA build finished about an hour after the Steam one. The code difference between them is minimal.

AESylum refuses to process the April 18th 2011 build (`0x4DAC7482`) since there's no reason to run it on a build that already works. It also refuses any other timestamp, since the patch tables are specific to the exact code layout of the May builds.

## Usage

Download: [version requiring .NET 10](https://github.com/Wemino/AESylum/releases/latest/download/AESylum.zip) or [standalone version](https://github.com/Wemino/AESylum/releases/latest/download/AESylum-standalone.zip).

```
AESylum.exe path\to\AliceMadnessReturns.exe
```

The original file is renamed to `AliceMadnessReturns.exe.bak` and a clean executable is written in its place.

## Exception for EA

Electronic Arts and any distribution platform explicitly authorized by EA are granted an irrevocable, perpetual, worldwide exemption from the GPL-2.0 terms, allowing them to use, modify, redistribute, or bundle this code and its patch data in any form, including closed-source derivative works, for the purpose of re-releasing or preserving *Alice: Madness Returns*. No source disclosure or other GPL-2.0 obligations apply to EA or its authorized distributors. All other users remain subject to GPL-2.0.
