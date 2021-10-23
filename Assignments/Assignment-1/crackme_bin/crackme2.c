
int callSuccess(int param_1,longlong param_2,undefined8 param_3,undefined8 param_4)

{
  char *pcVar1;
  ulonglong uVar2;
  longlong lVar3;
  char **ppcVar4;
  undefined4 local_38;
  undefined uStack49;
  undefined4 uStack52;
  ulonglong local_30;
  
  lVar3 = param_2;
  FUN_140001700();
  local_30 = DAT_14000b050 ^ (ulonglong)&stack0xffffffffffffffd8;
  uStack52 = CONCAT13(uStack49,0x7a747e);
  local_38 = 0x70687a6b;
  if (param_1 == 2) {
    ppcVar4 = (char **)(param_2 + 8);
    if (ppcVar4 < (char **)0x9) {
LAB_1400011ad:
      do {
        invalidInstructionException();
      } while( true );
    }
    if (((ulonglong)ppcVar4 & 7) != 0) goto LAB_1400011b7;
    uVar2 = FUN_140001f70(*ppcVar4,0xb);
    if (uVar2 != 7) goto LAB_140001185;
    pcVar1 = *ppcVar4;
    uVar2 = 0;
    do {
      if ((((pcVar1 + uVar2 < pcVar1) || (pcVar1 == (char *)0x0)) || (pcVar1 + uVar2 == (char *)0x0)
          ) || (CARRY8((ulonglong)&local_38,uVar2))) goto LAB_1400011ad;
      if ((byte)pcVar1[uVar2] + 5 != (uint)*(byte *)((longlong)&local_38 + uVar2)) {
        if ((longlong)&local_38 + uVar2 == 0) goto LAB_1400011ad;
        if (pcVar1[uVar2] + 5 != (int)(char)*(byte *)((longlong)&local_38 + uVar2))
        goto LAB_140001185;
      }
      uVar2 = uVar2 + 1;
    } while (uVar2 != 7);
    putSuccess();
  }
  else {
    FUN_140001020("usage: ./crackme Keyguess",lVar3,param_3,param_4);
LAB_140001185:
    FUN_140001090();
  }
  if (DAT_14000b050 == (local_30 ^ (ulonglong)&stack0xffffffffffffffd8)) {
    return 0;
  }
  FUN_140002090();
LAB_1400011b7:
  do {
    invalidInstructionException();
  } while( true );
}

void main (){
  callSuccess
}