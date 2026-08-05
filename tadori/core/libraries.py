"""Telling the app's own code apart from the libraries it bundles.

A released APK contains far more third-party code than app code. AndroidX alone
calls ``setComponentEnabledSetting``, reflects into hidden APIs and enumerates
packages — attribute those to the app and every real app looks hostile.

So matches carry a provenance, and library matches are hidden by default. The
list is a curated allowlist of *widely used* libraries: malware that names
itself ``androidx.work`` would be shielded, which is why ``--include-libraries``
exists and why the count of hidden matches is always reported.
"""

from __future__ import annotations

#: Class-name prefixes (smali form) of code that ships with, but is not, the app.
LIBRARY_PREFIXES: tuple[str, ...] = (
    "Landroid/support/",
    "Landroidx/",
    "Lkotlin/",
    "Lkotlinx/",
    "Ljava/",
    "Ljavax/",
    "Lsun/",
    "Ldalvik/",
    "Lorg/jetbrains/",
    "Lcom/google/android/gms/",
    "Lcom/google/android/material/",
    "Lcom/google/firebase/",
    "Lcom/google/common/",
    "Lcom/google/gson/",
    "Lcom/google/protobuf/",
    "Lcom/squareup/",
    "Lokhttp3/",
    "Lokio/",
    "Lretrofit2/",
    "Ldagger/",
    "Lhilt_aggregated_deps/",
    "Lio/reactivex/",
    "Lio/ktor/",
    "Lio/grpc/",
    "Lorg/apache/",
    "Lorg/json/",
    "Lorg/slf4j/",
    "Lorg/bouncycastle/",
    "Lorg/acra/",
    "Lcom/bumptech/glide/",
    "Lcoil/",
    "Lcoil3/",
    "Lcom/facebook/",
    "Lcom/airbnb/",
    "Lcom/afollestad/",
    "Lcom/fasterxml/",
    "Lorg/greenrobot/",
    "Lio/sentry/",
    "Lcom/bugsnag/",
    "Lcom/microsoft/appcenter/",
    "Lcom/unity3d/",
    "Lio/flutter/",
    "Lcom/facebook/react/",
    "L_COROUTINE/",
    "Lj$/",  # desugared JDK APIs
)

APP = "app"
LIBRARY = "library"


def provenance(location: str) -> str:
    """``app`` or ``library``, judged from the class the match sits in."""
    class_name = location.split("->", 1)[0]
    return LIBRARY if class_name.startswith(LIBRARY_PREFIXES) else APP


def is_library(class_name: str) -> bool:
    return class_name.startswith(LIBRARY_PREFIXES)
