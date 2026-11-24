Unicode true
Name "Barnacle archive test"
OutFile "${OUTPUT}"
SetCompressor ${OPTIONS} ${CODEC}
RequestExecutionLevel user
SilentInstall silent
CRCCheck force
Section
  File "first.txt"
  File "second.txt"
SectionEnd
