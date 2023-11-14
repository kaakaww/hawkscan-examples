import org.jetbrains.kotlin.konan.file.File.Companion.userHome

plugins {
    kotlin("jvm") version "1.8.22"
}

val kotlinVersion = "1.8.22"
val hawkScriptSdkVersion = "3.4.2"

kotlin {
    sourceSets {
        main {
            kotlin {
                srcDirs(
                    "scripts/examples/authentication",
                    "scripts/examples/session",
                    "scripts/examples/httpsender",
                    "scripts/examples/active",
                    "scripts/examples/proxy",
                    "scripts/templates/authentication",
                    "scripts/templates/session",
                    "scripts/templates/httpsender",
                    "scripts/templates/proxy",
                )
            }
        }
    }
}

repositories {
    mavenCentral()
}

dependencies {
    compileOnly("org.jetbrains.kotlin:kotlin-stdlib:$kotlinVersion")
    compileOnly("org.jetbrains.kotlin:kotlin-script-runtime:$kotlinVersion")
    // change to location of the hawkscript-sdk-<version>/ directory.
    compileOnly(zipTree("$userHome/Downloads/hawkscript-sdk-$hawkScriptSdkVersion.zip"))
}
