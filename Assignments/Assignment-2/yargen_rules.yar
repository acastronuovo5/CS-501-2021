/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2021-10-18
   Identifier: 
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule BU_IT_Support {
   meta:
      description = " - file BU-IT-Support.doc"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-10-18"
      hash1 = "e1edd1835f00026da05761a0be84779ac6383b00872366ebdb8411a5eeb7792f"
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
      $s10 = "hell.exe" fullword ascii
      $s11 = "http://www.brianbaldeck.com" fullword ascii
      $s12 = "C:\\Windows\\System32\\stdole2.tlb" fullword ascii
      $s13 = "*\\G{00020430-0000-0000-C000-000000000046}#2.0#0#C:\\Windows\\System32\\stdole2.tlb#OLE Automation" fullword wide
      $s14 = "WScript.Shell" fullword ascii
      $s15 = "adobe.com/xap/1.0/sType/ResourceRef#\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\" xmlns:xmpRights=\"http://ns.adobe.com/xap/1" ascii
      $s16 = "https://ch0nky.chickenkiller.com/ItSupport.exe'" fullword ascii
      $s17 = "C:\\malware\\ch0nky.txt" fullword ascii
      $s18 = "ell.exe /c " fullword ascii
      $s19 = "//ns.adobe.com/xap/1.0/\" xmlns:xmpMM=\"http://ns.adobe.com/xap/1.0/mm/\" xmlns:stRef=\"http://ns.adobe.com/xap/1.0/sType/Resour" ascii
      $s20 = "s:xmpMM=\"http://ns.adobe.com/xap/1.0/mm/\" xmlns:stEvt=\"http://ns.adobe.com/xap/1.0/sType/ResourceEvent#\" xmlns:stRef=\"http:" ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 2000KB and
      1 of ($x*) and 4 of them
}

rule ITSupport {
   meta:
      description = " - file ITSupport.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-10-18"
      hash1 = "9d5a1eecd236d61e3242850d0487808091fc5d0db0a3e45be8970bdbf1fdff88"
   strings:
      $s1 = "http://ch0nky.chickenkiller.com/update.exe" fullword wide
      $s2 = "execute once failure in __cxa_get_globals_fast()" fullword ascii
      $s3 = "MicrosoftUpdate.exe" fullword wide
      $s4 = "mutex lock failed" fullword ascii
      $s5 = "C:\\malware\\ch0nky.txt" fullword wide
      $s6 = "%s failed to release mutex" fullword ascii
      $s7 = "recursive_mutex constructor failed" fullword ascii
      $s8 = "%s failed to acquire mutex" fullword ascii
      $s9 = "recursive_mutex lock failed" fullword ascii
      $s10 = "Personality continued unwind at the target frame!" fullword ascii
      $s11 = "NSt3__115__time_get_tempIcEE" fullword ascii
      $s12 = "N12_GLOBAL__N_116itanium_demangle24ForwardTemplateReferenceE" fullword ascii
      $s13 = "NSt3__115__time_get_tempIwEE" fullword ascii
      $s14 = "libunwind: %s - %s" fullword ascii
      $s15 = "condition_variable::timed wait: mutex not locked" fullword ascii
      $s16 = "condition_variable::wait: mutex not locked" fullword ascii
      $s17 = "00010203040506070809101112131415161718192021222324252627282930313233343536373839404142434445464748495051525354555657585960616263" ascii
      $s18 = "646566676869707172737475767778798081828384858687888990919293949596979899libunwind: %s - %s" fullword ascii
      $s19 = "recursive_timed_mutex lock limit reached" fullword ascii
      $s20 = "template parameter object for " fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

