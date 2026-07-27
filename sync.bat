@echo off
echo ==================================================
echo 🚀 جاري رفع وتحديث مشروع محفظة على GitHub تلقائياً...
echo ==================================================
set GIT_EXE="C:\Program Files\Git\cmd\git.exe"
%GIT_EXE% init
%GIT_EXE% branch -M main
%GIT_EXE% add .
%GIT_EXE% commit -m "تحديث منصة محفظة"
%GIT_EXE% push -u origin main --force
echo ==================================================
echo 🎉 تم رفع التحديث بنجاح! موقعك على Render سيتحدث آلياً خلال 30 ثانية.
echo ==================================================
