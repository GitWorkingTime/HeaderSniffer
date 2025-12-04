# HeaderSniffer
<img width="980" height="203" alt="Screenshot 2025-12-04 123059" src="https://github.com/user-attachments/assets/1abc2844-6b9d-48b7-bdcc-35430a4a62e6" />
HeaderSniffer is a python script that takes in a file path and double checks if the header file extension is really the file format. This could be used as a precautionary step before executing or opening a file. Hackers may disguise their file under another file extension afterall. The inspiration for this project came from this [video](https://www.youtube.com/watch?v=10CLi-OUy4E) when I was just bored.

## Getting Started
This is assuming that you already had Git installed. If not, there are lots of resources online such as [this](https://www.theodinproject.com/lessons/foundations-setting-up-git) to get you started. As well, make sure to have python installed on your machine too! [Installing Python](https://www.geeksforgeeks.org/python/download-and-install-python-3-latest-version/)
```
1.) Clone the Repo:
    git clone git@github.com:GitWorkingTime/HeaderSniffer.git (For SSH)
    git clone https://github.com/GitWorkingTime/HeaderSniffer.git (For HTTPS)

2.) Open the Directory
```

## Usage
```
1.) Enter the directory via cd in the terminal
2.) Run python header_sniffer.py
3.) Choose a file you want to check and copy its file path by right-clicking on the file and 
    selecting "Copy File as Path" or Ctrl + Shift + C on windows
4.) View the logs. This will be the format:
    [File Name]:             (The name of the file)
    [Magic Number (hex)]:    (Magic number in hexadecimal)
    [Real File Extension]:   (Real file format found based on magic number)
    [File Extension Header]: (File extension found in the header)

    Either "Correct file type." Or "Warning!"

    [Additional Stats]:
        [Size]:          (Number of bytes)
        [Last modified]: (date)
        [Last Accessed]: (date)
        [Created]:       (date)
5.) If you wish to exit, just type in 'exit'
```
## Supported Document Types:
| Type                   | File Format                                              |
|------------------------|----------------------------------------------------------|
| Images                 | - png - jpg - jpeg - gif - bmp - tif - tiff - webp - ico |
| Archives / Compression | - zip - gz - tar - 7z - rar                              |
| Documents              | - pdf - ps - ole2 (Generic OLE2: doc, xls, ppt)          |
| Audio                  | - mp3 - mp3_v1 (MP3 Varient) - wav - flac - ogg - midi   |
| Video                  | - mp4 - avi - mov                                        |
| Executables / Systems  | - exe - dll - elf - class - sh                           |
| Font Files             | - tff - otf                                              |
| Disk Images            | - iso                                                    |
| Other                  | - xml - rtf - swf - wasm                                 |

### Other
- xml
- rtf
- swf
- wasm
