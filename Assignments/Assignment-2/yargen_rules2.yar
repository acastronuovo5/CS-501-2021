/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2021-10-29
   Identifier: AllChonky
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule Boston_University_IT_Help_Center {
   meta:
      description = "AllChonky - file Boston-University-IT-Help-Center.doc"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-10-29"
      hash1 = "9b6d84c11470f3873f938a2517a0b935f73258521de9fbaa0213e6e94a041ce2"
   strings:
      $x1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 6.0-c002 79.164488, 2020/07/" ascii
      $x2 = "https://ch0nky.chickenkiller.com/login.exe" fullword wide
      $x3 = "C:\\Program Files\\Common Files\\Microsoft Shared\\VBA\\VBA7.1\\VBE7.DLL" fullword ascii
      $x4 = "C:\\Program Files\\Common Files\\Microsoft Shared\\OFFICE16\\MSO.DLL" fullword ascii
      $x5 = "powershell.exe kill -processname winword'" fullword ascii
      $s6 = "https://ch0nky.chickenkiller.com/login.exe'" fullword ascii
      $s7 = "://www.brianbaldeck.com\" crs:RawFileName=\"DSC_5822.NEF\" crs:Version=\"11.3\" crs:ProcessVersion=\"6.7\" crs:WhiteBalance=\"As" ascii
      $s8 = "*\\G{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}#2.8#0#C:\\Program Files\\Common Files\\Microsoft Shared\\OFFICE16\\MSO.DLL#Microsoft " wide
      $s9 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c138 79.159824, 2016/09/" ascii
      $s10 = " INCLUDEPICTURE \"https://www.bu.edu/tech/wp-content/themes/bu-tech-2014/images/bu-techweb-logo.png\" \\* MERGEFORMATINET " fullword ascii
      $s11 = "*\\G{000204EF-0000-0000-C000-000000000046}#4.2#9#C:\\Program Files\\Common Files\\Microsoft Shared\\VBA\\VBA7.1\\VBE7.DLL#Visual" wide
      $s13 = "http://www.brianbaldeck.com" fullword ascii
      $s14 = "C:\\Windows\\System32\\stdole2.tlb" fullword ascii
      $s15 = "*\\G{00020430-0000-0000-C000-000000000046}#2.0#0#C:\\Windows\\System32\\stdole2.tlb#OLE Automation" fullword wide
      $s16 = "VBE7.DLL" fullword ascii
      $s17 = "C:\\malware\\ch0nky.txt" fullword wide
      $s18 = "adobe.com/xap/1.0/sType/ResourceRef#\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\" xmlns:xmpRights=\"http://ns.adobe.com/xap/1" ascii
      $s19 = "WScript.Shell" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule BU_IT_Support {
   meta:
      description = "AllChonky - file BU-IT-Support.doc"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-10-29"
      hash1 = "e1edd1835f00026da05761a0be84779ac6383b00872366ebdb8411a5eeb7792f"
   strings:
      $x1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 6.0-c002 79.164488, 2020/07/" ascii
      $x2 = "C:\\Program Files\\Common Files\\Microsoft Shared\\VBA\\VBA7.1\\VBE7.DLL" fullword ascii
      $x3 = "C:\\Program Files\\Common Files\\Microsoft Shared\\OFFICE16\\MSO.DLL" fullword ascii
      $x4 = "powershell.exe kill -processname winword'" fullword ascii
      $x5 = "C:\\malware\\ch0nky.txt" fullword ascii
      $s5 = "://www.brianbaldeck.com\" crs:RawFileName=\"DSC_5822.NEF\" crs:Version=\"11.3\" crs:ProcessVersion=\"6.7\" crs:WhiteBalance=\"As" ascii
      $s6 = "*\\G{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}#2.8#0#C:\\Program Files\\Common Files\\Microsoft Shared\\OFFICE16\\MSO.DLL#Microsoft " wide
      $s7 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c138 79.159824, 2016/09/" ascii
      $s8 = " INCLUDEPICTURE \"https://www.bu.edu/tech/wp-content/themes/bu-tech-2014/images/bu-techweb-logo.png\" \\* MERGEFORMATINET " fullword ascii
      $s9 = "*\\G{000204EF-0000-0000-C000-000000000046}#4.2#9#C:\\Program Files\\Common Files\\Microsoft Shared\\VBA\\VBA7.1\\VBE7.DLL#Visual" wide
      $s11 = "http://www.brianbaldeck.com" fullword ascii
      $s12 = "C:\\Windows\\System32\\stdole2.tlb" fullword ascii
      $s13 = "*\\G{00020430-0000-0000-C000-000000000046}#2.0#0#C:\\Windows\\System32\\stdole2.tlb#OLE Automation" fullword wide
      $s15 = "adobe.com/xap/1.0/sType/ResourceRef#\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\" xmlns:xmpRights=\"http://ns.adobe.com/xap/1" ascii
      $s16 = "WScript.Shell" fullword ascii
      $s17 = "https://ch0nky.chickenkiller.com/ItSupport.exe'" fullword ascii
      $s19 = "s:xmpMM=\"http://ns.adobe.com/xap/1.0/mm/\" xmlns:stEvt=\"http://ns.adobe.com/xap/1.0/sType/ResourceEvent#\" xmlns:stRef=\"http:" ascii
      $s20 = "//ns.adobe.com/xap/1.0/\" xmlns:aux=\"http://ns.adobe.com/exif/1.0/aux/\" xmlns:photoshop=\"http://ns.adobe.com/photoshop/1.0/\"" ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule ItSupport {
   meta:
      description = "AllChonky - file ItSupport.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-10-29"
      hash1 = "58189cbd4e6dc0c7d8e66b6a6f75652fc9f4afc7ce0eba7d67d8c3feb0d5381f"
   strings:
      $x1 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii
      $s2 = "<dpiAware  xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" fullword ascii
      $s3 = "processorArchitecture=\"*\"" fullword ascii
      $s4 = "processorArchitecture=\"amd64\"" fullword ascii
      $s5 = "publicKeyToken=\"6595b64144ccf1df\"" fullword ascii
      $s9 = "name=\"Microsoft.Windows.Common-Controls\"" fullword ascii
      $s11 = "10.0.19041.1 (WinBuild.160101.0800)" fullword wide
      $s12 = "\"CalculatorStarted\"" fullword ascii /* Goodware String - occured 2 times */
      $s13 = "CalculatorWinMain" fullword ascii /* Goodware String - occured 2 times */
      $s14 = "CalculatorStarted" fullword ascii /* Goodware String - occured 2 times */
      $s15 = "MicrosoftCalculator" fullword ascii /* Goodware String - occured 2 times */
      $s16 = "IDI_CALC_ICON" fullword wide /* Goodware String - occured 2 times */
      $s17 = "<requestedPrivileges>" fullword ascii
      $s19 = "6595b64144ccf1df" ascii 

   condition:
      uint16(0) == 0x5a4d and filesize < 80KB and
      8 of them
}

rule AllChonky_update {
   meta:
      description = "AllChonky - file update.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-10-29"
      hash1 = "da7d6cebf27b080486d471f56b8145ba2a4ae862fae6e9a8ce0c7ed8ac9a6de1"
   strings:
      $s1 = "powershell.exe /c " fullword ascii
      $s2 = "ch0nky.chickenkiller.com" fullword wide
      $s3 = "C:\\malware\\ch0nky.txt" fullword wide
      $x5 = "<requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii
      $s6 = "auth=d50fb4bbb04a6a28ec1c56ecbc463510" fullword ascii
      $s7 = "&computeH" fullword ascii
      $s8 = "&computer=" fullword ascii
      $s9 = "/register.php" fullword wide
      $s10 = "/checkin.php" fullword wide
      $s11 = "AWAVATVWSH" fullword ascii
      $s12 = "AWAVATVWUSH" fullword ascii
      $s13 = "UAWAVVWSH" fullword ascii
      $s14 = "AWAVAUATVWSH" fullword ascii
      $s15 = "UAVVWSH" fullword ascii
      $s16 = "AWAVAUATVWUSH" fullword ascii
      $s17 = "UAWAVAUATVWSH" fullword ascii
      $s18 = "UAWAVAUATVWS" fullword ascii
      $s19 = "AWAVVWSH" fullword ascii
      $s20 = "d50fb4bbb04a6a28ec1c56ecbc463510" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 100KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _Boston_University_IT_Help_Center_BU_IT_Support_0 {
   meta:
      description = "AllChonky - from files Boston-University-IT-Help-Center.doc, BU-IT-Support.doc"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-10-29"
      hash1 = "9b6d84c11470f3873f938a2517a0b935f73258521de9fbaa0213e6e94a041ce2"
      hash2 = "e1edd1835f00026da05761a0be84779ac6383b00872366ebdb8411a5eeb7792f"
   strings:
      $x1 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 6.0-c002 79.164488, 2020/07/" ascii
      $x2 = "C:\\Program Files\\Common Files\\Microsoft Shared\\VBA\\VBA7.1\\VBE7.DLL" fullword ascii
      $x3 = "C:\\Program Files\\Common Files\\Microsoft Shared\\OFFICE16\\MSO.DLL" fullword ascii
      $x4 = "powershell.exe kill -processname winword'" fullword ascii
      $s5 = "://www.brianbaldeck.com\" crs:RawFileName=\"DSC_5822.NEF\" crs:Version=\"11.3\" crs:ProcessVersion=\"6.7\" crs:WhiteBalance=\"As" ascii
      $s6 = "*\\G{2DF8D04C-5BFA-101B-BDE5-00AA0044DE52}#2.8#0#C:\\Program Files\\Common Files\\Microsoft Shared\\OFFICE16\\MSO.DLL#Microsoft " wide
      $s7 = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.6-c138 79.159824, 2016/09/" ascii
      $s8 = " INCLUDEPICTURE \"https://www.bu.edu/tech/wp-content/themes/bu-tech-2014/images/bu-techweb-logo.png\" \\* MERGEFORMATINET " fullword ascii
      $s9 = "*\\G{000204EF-0000-0000-C000-000000000046}#4.2#9#C:\\Program Files\\Common Files\\Microsoft Shared\\VBA\\VBA7.1\\VBE7.DLL#Visual" wide
      $s11 = "http://www.brianbaldeck.com" fullword ascii
      $s12 = "C:\\Windows\\System32\\stdole2.tlb" fullword ascii
      $s13 = "*\\G{00020430-0000-0000-C000-000000000046}#2.0#0#C:\\Windows\\System32\\stdole2.tlb#OLE Automation" fullword wide
      $x14 = "C:\\malware\\ch0nky.txt" fullword ascii
      $s15 = "adobe.com/xap/1.0/sType/ResourceRef#\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\" xmlns:xmpRights=\"http://ns.adobe.com/xap/1" ascii
      $s16 = "WScript.Shell" fullword ascii
      $s18 = "s:xmpMM=\"http://ns.adobe.com/xap/1.0/mm/\" xmlns:stEvt=\"http://ns.adobe.com/xap/1.0/sType/ResourceEvent#\" xmlns:stRef=\"http:" ascii
      $s19 = "//ns.adobe.com/xap/1.0/\" xmlns:aux=\"http://ns.adobe.com/exif/1.0/aux/\" xmlns:photoshop=\"http://ns.adobe.com/photoshop/1.0/\"" ascii
      $s20 = "//ns.adobe.com/xap/1.0/\" xmlns:xmpMM=\"http://ns.adobe.com/xap/1.0/mm/\" xmlns:stRef=\"http://ns.adobe.com/xap/1.0/sType/Resour" ascii
   condition:
      ( uint16(0) == 0xcfd0 and filesize < 2000KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

