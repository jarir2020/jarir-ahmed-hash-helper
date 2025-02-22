<?php

// autoload_static.php @generated by Composer

namespace Composer\Autoload;

class ComposerStaticInita35c5f9b9d6cd95dd6218f9f389de21e
{
    public static $prefixLengthsPsr4 = array (
        'J' => 
        array (
            'JarirAhmed\\HashHelper\\Tests\\' => 28,
            'JarirAhmed\\HashHelper\\' => 22,
        ),
        'B' => 
        array (
            'Base32\\' => 7,
        ),
    );

    public static $prefixDirsPsr4 = array (
        'JarirAhmed\\HashHelper\\Tests\\' => 
        array (
            0 => __DIR__ . '/../..' . '/tests',
        ),
        'JarirAhmed\\HashHelper\\' => 
        array (
            0 => __DIR__ . '/../..' . '/src',
        ),
        'Base32\\' => 
        array (
            0 => __DIR__ . '/..' . '/christian-riesen/base32/src',
        ),
    );

    public static $classMap = array (
        'Composer\\InstalledVersions' => __DIR__ . '/..' . '/composer/InstalledVersions.php',
    );

    public static function getInitializer(ClassLoader $loader)
    {
        return \Closure::bind(function () use ($loader) {
            $loader->prefixLengthsPsr4 = ComposerStaticInita35c5f9b9d6cd95dd6218f9f389de21e::$prefixLengthsPsr4;
            $loader->prefixDirsPsr4 = ComposerStaticInita35c5f9b9d6cd95dd6218f9f389de21e::$prefixDirsPsr4;
            $loader->classMap = ComposerStaticInita35c5f9b9d6cd95dd6218f9f389de21e::$classMap;

        }, null, ClassLoader::class);
    }
}
