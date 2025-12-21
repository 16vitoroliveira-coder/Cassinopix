<?php

namespace App\Providers;

use Illuminate\Support\ServiceProvider;
use TomatoPHP\FilamentSimpleTheme\FilamentSimpleThemePlugin;
use Filament\Panel;

class FilamentThemeServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        //
    }

    public function boot(): void
    {
        Panel::configureUsing(function (Panel $panel) {
            $panel->plugins([
                FilamentSimpleThemePlugin::make(),
            ]);
        });
    }
}
