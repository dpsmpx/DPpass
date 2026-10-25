# R8 для release (D-91): сжатие и оптимизация, имена — как в исходниках.
# Запись о падении и журнал устройства (D-26) читаются без файла
# сопоставления; спрятать приложение переименованием всё равно нельзя —
# его выдают библиотека ядра, геоданные и строки (D-13: не обещаем
# незаметности).
-dontobfuscate
# Без оптимизации и со своими номерами строк: встроенный метод пропал бы из
# стека, а строки и файлы стали бы номерами карты. Главная экономия — от
# сжатия (6,9 → ~1 МБ dex), оптимизация к ней почти ничего не прибавляет.
-dontoptimize
-keepattributes SourceFile,LineNumberTable

# JNI (D-25): имена native-методов объекта XrayJni — часть символов
# libdppassxray.so (Java_com_dpsmpx_dppass_engine_xray_XrayJni_*).
-keep class com.dpsmpx.dppass.engine.xray.XrayJni {
    native <methods>;
}

# Защитник сокетов: мост находит его по имени (tools/xray/jni/jni.go —
# FindClass «com/dpsmpx/dppass/engine/SocketProtector», метод protect (I)Z).
# Из Kotlin protect не вызывается — без правила R8 убрал бы реализации или
# слил интерфейс с единственной.
-keep interface com.dpsmpx.dppass.engine.SocketProtector {
    boolean protect(int);
}
-keepclassmembers class * implements com.dpsmpx.dppass.engine.SocketProtector {
    boolean protect(int);
}
