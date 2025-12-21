<?php

namespace App\Filament\Pages;

use App\Models\ConfigRoundsFree;
use App\Models\Game;
use App\Models\GamesKey;
use App\Models\User;
use App\Services\PlayFiverService;
use Filament\Forms\Components\Section;
use Filament\Forms\Components\Select;
use Filament\Forms\Components\TextInput;
use Filament\Forms\Concerns\InteractsWithForms;
use Filament\Forms\Contracts\HasForms;
use Filament\Forms\Form;
use Filament\Notifications\Notification;
use Filament\Pages\Page;
use Filament\Support\Exceptions\Halt;
use Filament\Tables;
use Filament\Tables\Actions\CreateAction;
use Filament\Tables\Actions\DeleteAction;
use Filament\Tables\Columns\TextColumn;
use Filament\Tables\Concerns\InteractsWithTable;
use Filament\Tables\Contracts\HasTable;
use Illuminate\Database\Eloquent\Builder;

class RoundsFreePage extends Page implements HasForms, HasTable
{
    use InteractsWithForms;
    use InteractsWithTable;

    protected static string $view  = 'filament.pages.rounds-free-page';
    protected static ?string $title = 'Rodadas Grátis';

    public static function canView(): bool
    {
        if (!auth()->check()) {
            return false;
        }
        return auth()->user()->hasRole('admin');
    }

    public ?array $data = [];
    public ?GamesKey $setting;

    public function mount(): void
    {
        $this->form->fill();
    }

    public function form(Form $form): Form
    {
        $users = User::pluck('email', 'email');
        $games = Game::pluck('game_name', 'game_code');

        return $form
            ->schema([
                Section::make('Rodadas Grátis')
                    ->schema([
                        Select::make('email')
                            ->label('Player')
                            ->options($users)
                            ->searchable()
                            ->required(),
                        Select::make('game_code')
                            ->label('Jogo')
                            ->options($games)
                            ->searchable()
                            ->required(),
                        TextInput::make('rounds')
                            ->label('Quantidade de rodadas')
                            ->numeric()
                            ->rules(['min:1', 'max:30'])
                            ->required()
                            ->maxLength(191),
                    ])
                    ->columns(3),
                Section::make('Confirmação de Alteração')
                    ->schema([
                        TextInput::make('admin_password')
                            ->label('Senha de 2FA')
                            ->password()
                            ->required()
                            ->dehydrateStateUsing(fn($state) => null),
                    ]),
            ])
            ->statePath('data');
    }

    protected function getTableQuery(): Builder
    {
        return ConfigRoundsFree::with('game');
    }

    protected function getTableColumns(): array
    {
        return [
            TextColumn::make('game.game_name')->label('Nome do Jogo')->sortable(),
            TextColumn::make('game_code')->label('Código do Jogo')->sortable(),
            TextColumn::make('spins')->label('Rodadas')->sortable(),
            TextColumn::make('value')->label('Valor')->money('BRL', true)->sortable(),
            TextColumn::make('created_at')->label('Criado em')->dateTime('d/m/Y H:i')->sortable(),
        ];
    }

    protected function getTableActions(): array
    {
        return [
            DeleteAction::make()
                ->label('Apagar')
                ->requiresConfirmation()
                ->modalHeading('Confirmar Exclusão')
                ->modalSubheading('Tem certeza que deseja apagar esta configuração?'),
        ];
    }

    protected function getTableHeaderActions(): array
    {
        return [
            CreateAction::make()
                ->label('Criar configuração')
                ->modalHeading('Nova Configuração de Rodadas Grátis')
                ->modalWidth('lg')
                // Impede o 'Create Another' default
                ->disableCreateAnother()
                // Retorna o registro criado para evitar null
                ->using(function (array $data) {
                    return ConfigRoundsFree::create($data);
                })
                ->form([
                    Select::make('game_code')
                        ->label('Jogo')
                        ->options(Game::pluck('game_name', 'game_code'))
                        ->searchable()
                        ->required(),

                    TextInput::make('spins')
                        ->label('Quantidade de Rodadas')
                        ->numeric()
                        ->rules(['integer', 'min:1'])
                        ->required(),

                    TextInput::make('value')
                        ->label('Valor (R$)')
                        ->numeric()
                        ->rules(['numeric', 'min:0'])
                        ->required(),
                ]),
        ];
    }

    protected function getTableFilters(): array
    {
        return [];
    }

    public function submit(): void
    {
        try {
            if (env('APP_DEMO')) {
                Notification::make()
                    ->title('Atenção')
                    ->body('Não é possível alterar em modo demo.')
                    ->danger()
                    ->send();
                return;
            }

            if (
                !isset($this->data['admin_password']) ||
                $this->data['admin_password'] !== env('TOKEN_DE_2FA')
            ) {
                Notification::make()
                    ->title('Acesso Negado')
                    ->body('Senha de 2FA incorreta.')
                    ->danger()
                    ->send();
                return;
            }

            $dados = [
                'username'  => $this->data['email'],
                'game_code' => $this->data['game_code'],
                'rounds'    => $this->data['rounds'],
            ];
            $result = PlayFiverService::RoundsFree($dados);

            if ($result['status']) {
                Notification::make()
                    ->title('Rodadas grátis')
                    ->body('Agendamento realizado com sucesso.')
                    ->success()
                    ->send();

                $this->data = [];
                $this->form->fill();
            } else {
                Notification::make()
                    ->title('Rodadas grátis')
                    ->body($result['message'])
                    ->danger()
                    ->send();
            }
        } catch (Halt $e) {
            Notification::make()
                ->title('Erro')
                ->body('Não foi possível completar a operação.')
                ->danger()
                ->send();
        }
    }
}
