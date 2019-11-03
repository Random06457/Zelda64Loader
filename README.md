# Majora's Mask 64 Loader
 Ghidra Loader for Majora's Mask 64 (WIP)
 
 This can load a Majora's Mask ROM either as a single file or as a file system.
 
 When a ROM is loaded as a "Single File", the loader will create the nintendo 64's memory layout, load and decompress the "code" file and load the overlay files specified by the overlay table used by the graph thread.
 
 <img src="https://raw.githubusercontent.com/Random0666/Useless-stuff/master/Mm64Loader/ghidra_loader.png" width=40%/>
 
 When a ROM is loaded as a "File System", the loader will simply parse the DMA entries and let you extract them.
 
<img src="https://raw.githubusercontent.com/Random0666/Useless-stuff/master/Mm64Loader/ghidra_fs.png" width=50%/>
 
# Currently supported versions:
- Japan 1.0 (zelda@srd44 00-03-31 02:22:11)
- Japan 1.1 (zelda@srd44 00-04-04 09:34:16)
- USA Kiosk Demo (zelda@srd44.00-07-12 16:14:06)
- USA 1.0	(zelda@srd44 00-07-31 17:04:16)
- Europe 1.0 (zelda@srd44 00-09-25 11:16:53)
- Europe 1.1 Debug (zelda@srd44 00-09-29 09:29:05)
- Europe 1.1 (zelda@srd44 00-09-29 09:29:41)