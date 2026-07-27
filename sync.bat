@echo off
echo ==================================================
echo 🚀 جاري رفع وتحديث مشروع محفظة على GitHub تلقائياً...
echo ==================================================
set GIT_EXE="C:\Program Files\Git\cmd\git.exe"
%GIT_EXE% init
%GIT_EXE% remote remove origin 2>nul
%GIT_EXE% remote add origin https://github.com/mo7medelbakry/maahfaztk.git
%GIT_EXE% branch -M main
%GIT_EXE% add .
%GIT_EXE% commit -m "تحديث تلقائي للمنصة من Antigravity"
%GIT_EXE% push -u origin main
echo ==================================================
echo 🎉 تم رفع التحديث بنجاح! موقعك على Render سيتحدث آلياً خلال 30 ثانية.
echo ==================================================
