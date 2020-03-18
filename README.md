# Zelda 64 Loader
 Ghidra Loader for Zelda 64 (WIP)
 
 This can load a Majora's Mask or Ocarina Of Time ROM either as a single file or as a file system.
 
 When a ROM is loaded as a "Single File", the loader will create the nintendo 64's memory layout, load the `code` file and load all the overlay files it can find (see [Loaded overlays](#loaded-overlays) for more details).
 
 <img src="https://raw.githubusercontent.com/Random06457/Useless-stuff/master/Mm64Loader/ghidra_loader.png" width=40%/>
 
 When a ROM is loaded as a "File System", the loader will simply parse the DMA entries and let you extract them.
 
<img src="https://raw.githubusercontent.com/Random06457/Useless-stuff/master/Mm64Loader/ghidra_fs.png" width=50%/>

# Loaded overlays
The overlays the loader will seek for are the following:
 - GameState overlays
 - Actor overlays
 - "Effect Soft Sprite" (aka "Effect SS2") overlays
 - `kaleido_manager` overlays (`player_actor` and `kaleido_scope`)
 - `map_mark_data` (specific to Ocarina Of Time)
 - Transition effect overlays (specific to Majora's Mask)
 
# Currently supported versions:
### Majora's Mask

| Version | Build ID | Supported |
|----------|:-------------:|:------:|
| Japan 1.0 | zelda@srd44 00-03-31 02:22:11 | Yes |
| Japan 1.1 | zelda@srd44 00-04-04 09:34:16 | Yes |
| USA Debug | zelda@srd44.00-07-06 16:46:35 | No |
| USA Kiosk Demo | zelda@srd44 00-07-12 16:14:06 | Yes |
| USA 1.0 | zelda@srd44 00-07-31 17:04:16 | Yes |
| Europe 1.0 | zelda@srd44 00-09-25 11:16:53 | Yes |
| Europe 1.1 Debug | zelda@srd44 00-09-29 09:29:05 | Yes |
| Europe 1.1 | zelda@srd44 00-09-29 09:29:41 | Yes |
| USA GameCube | zelda@srd021j 03-08-26 04:20:25 | No |
| Europe GameCube | zelda@srd021j 03-10-04 00:40:20 | No |
| Japan GameCube | zelda@srd021j 03-11-06 01:25:18 | No |

### Ocarina Of Time

| Version | Build ID | Supported |
|----------|:-------------:|:------:|
| JP/US 1.0 | zelda@srd44 98-10-21 04:56:31 | Yes |
| JP/US 1.1 | zelda@srd44 98-10-26 10:58:45 | Yes |
| Europe 1.0 | zelda@srd44 98-11-10 14:34:22 | Yes |
| JP/US 1.2 | zelda@srd44 98-11-12 18:17:03 | Yes |
| Europe 1.1 | zelda@srd44 98-11-18 17:36:49 | Yes |
| Japan GameCube | zelda@srd022j 02-10-29 23:49:53 | Yes |
| Japan Master Quest | zelda@srd022j 02-10-30 00:15:15 | Yes |
| USA GameCube | zelda@srd022j 02-12-19 13:28:09 | Yes |
| USA Master Quest | zelda@srd022j 02-12-19 14:05:42 | Yes |
| Europe GameCube Debug | zelda@srd022j 03-02-13 19:46:49 | No |
| Europe Master Quest Debug | zelda@srd022j 03-02-21 00:16:31 | Yes |
| Europe GameCube | zelda@srd022j 03-02-21 20:12:23 | Yes |
| Europe Master Quest | zelda@srd022j 03-02-21 20:37:19 | Yes |
| Japan GameCube Zelda Collection | zelda@srd022j 03-10-08 21:53:00 | Yes |
| China iQue | build@toad.routefree.com 03-10-22 16:23:19 | No |
| Traditional Chinese iQue | tyu@linuxdev3 06-10-13 14:17:43 | No |