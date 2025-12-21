<?php

namespace App\Filament\Pages;

use App\Models\LogsRoundsFree;
use Filament\Pages\Page;
use Filament\Tables\Columns\CheckboxColumn;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Concerns\InteractsWithTable;
use Filament\Tables\Contracts\HasTable;
use Filament\Tables\Table;

class LogsRoundsFreePage extends Page implements HasTable
{
    use InteractsWithTable;

    protected static ?string $navigationIcon = 'heroicon-o-document-text';

    protected static string $view = 'filament.pages.logs-rounds-free-page';


    protected static ?string $title = 'Logs Rodadas Grátis';

    protected static ?string $slug = 'logs-rounds-free';
    public function table(Table $table): Table
    {
        return $table
            ->query(LogsRoundsFree::query()) 
            ->columns([
                TextColumn::make('username')->label('Usuário')->searchable(),
                TextColumn::make('game_code')->label('Jogo')->searchable(),
                CheckboxColumn::make('status')->label("Status")->disabled(),
                TextColumn::make('message')->label('Mensagem'),
                TextColumn::make('created_at')->label('Data')->dateTime('d/m/Y H:i'),
            ])
            ->defaultSort('created_at', 'desc');
    }
}
