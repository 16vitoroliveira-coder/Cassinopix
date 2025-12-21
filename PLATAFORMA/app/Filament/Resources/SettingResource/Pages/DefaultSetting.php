<?php

namespace App\Filament\Resources\SettingResource\Pages;

use App\Filament\Resources\SettingResource;
use App\Models\Setting;
use App\Models\User;
use AymanAlhattami\FilamentPageWithSidebar\Traits\HasPageSidebar;
use Filament\Forms\Components\FileUpload;
use Filament\Forms\Components\Group;
use Filament\Forms\Components\Section;
use Filament\Forms\Components\TextInput;
use Filament\Forms\Concerns\InteractsWithForms;
use Illuminate\Support\HtmlString;
use Filament\Forms\Contracts\HasForms;
use Filament\Forms\Form;
use Filament\Notifications\Notification;
use Filament\Resources\Pages\Page;
use Filament\Support\Exceptions\Halt;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Cache;
use Jackiedo\DotenvEditor\Facades\DotenvEditor;
use Livewire\Features\SupportFileUploads\TemporaryUploadedFile;
use Illuminate\Contracts\Support\Htmlable;
use Filament\Forms\Components\Textarea;
use Filament\Forms\Components\Toggle;

class DefaultSetting extends Page implements HasForms
{
    use HasPageSidebar, InteractsWithForms;

    protected static string $resource = SettingResource::class;

    protected static string $view = 'filament.resources.setting-resource.pages.default-setting';

    /**
     * @dev  
     * @param Model $record
     * @return bool
     */
    public static function canView(Model $record): bool
    {
        return auth()->user()->hasRole('admin');
    }

    /**
     * @return string|Htmlable
     */
    public function getTitle(): string | Htmlable
    {
        return __('AJUSTE OS DADOS DA PLATAFORMA'); 
    }

    public Setting $record;
    public ?array $data = [];

    /**
     * @dev  
     * @return void
     */
    public function mount(): void
    {   
        $envs = DotenvEditor::load(base_path('.env'));
        $setting = Setting::first();
        $this->record = $setting;
        $this->record->url_env = $envs->getValue("FILAMENT_BASE_URL");
        $this->form->fill($setting->toArray());
    }

    /**
     * @return void
     */
    public function save()
    {
        try {
            if(env('APP_DEMO')) {
                Notification::make()
                    ->title('Atenção')
                    ->body('Você não pode realizar está alteração na versão demo')
                    ->danger()
                    ->send();
                return;
            }

            $setting = Setting::find($this->record->id);

            $favicon   = $this->data['software_favicon'];
            $logoWhite = $this->data['software_logo_white'];
            $logoBlack = $this->data['software_logo_black'];
            $softwareBackground = $this->data['software_background'];

            if (is_array($softwareBackground) || is_object($softwareBackground)) {
                if(!empty($softwareBackground)) {
                    $this->data['software_background'] = $this->uploadFile($softwareBackground);

                    if(is_array($this->data['software_background'])) {
                        unset($this->data['software_background']);
                    }
                }
            }

            if (is_array($favicon) || is_object($favicon)) {
                if(!empty($favicon)) {
                    $this->data['software_favicon'] = $this->uploadFile($favicon);

                    if(is_array($this->data['software_favicon'])) {
                        unset($this->data['software_favicon']);
                    }
                }
            }

            if (is_array($logoWhite) || is_object($logoWhite)) {
                if(!empty($logoWhite)) {
                    $this->data['software_logo_white'] = $this->uploadFile($logoWhite);

                    if(is_array($this->data['software_logo_white'])) {
                        unset($this->data['software_logo_white']);
                    }
                }
            }

            if (is_array($logoBlack) || is_object($logoBlack)) {
                if(!empty($logoBlack)) {
                    $this->data['software_logo_black'] = $this->uploadFile($logoBlack);

                    if(is_array($this->data['software_logo_black'])) {
                        unset($this->data['software_logo_black']);
                    }
                }
            }

            $envs = DotenvEditor::load(base_path('.env'));

            $envs->setKeys([
                'APP_NAME' => $this->data['software_name'],
                'FILAMENT_BASE_URL' => $this->data['url_env']
            ]);

            $envs->save();

            if($setting->update($this->data)) {
                Cache::put('setting', $setting);

                Notification::make()
                    ->title('Dados alterados')
                    ->body('Dados alterados com sucesso!')
                    ->success()
                    ->send();

                redirect(route('filament.admin.resources.settings.index'));

            }
        } catch (Halt $exception) {
            return;
        }
    }

    /**
     * @dev  
     * @param Form $form
     * @return Form
     */
    public function form(Form $form): Form
    { 
        return $form
            ->schema([
                Section::make('ONDA GAMES CRIOU ESSA PLATAFORMA PARA VOCÊ')
                ->description(new HtmlString('
                    <div style="font-weight: 600; display: flex; align-items: center;">
                        SAIBA MAIS SOBRE NÓS. PARTICIPE DA NOSSA COMUNIDADE IGAMING. ACESSE AGORA! 
                        <a class="dark:text-white" 
                           style="
                                font-size: 14px;
                                font-weight: 600;
                                width: 127px;
                                display: flex;
                                background-color: #f800ff;
                                padding: 10px;
                                border-radius: 11px;
                                justify-content: center;
                                margin-left: 10px;
                           " 
                           href="https://ondagames.com" 
                           target="_blank">
                            SITE OFICIAL
                        </a>
                        <a class="dark:text-white" 
                           style="
                                font-size: 14px;
                                font-weight: 600;
                                width: 127px;
                                display: flex;
                                background-color: #f800ff;
                                padding: 10px;
                                border-radius: 11px;
                                justify-content: center;
                                margin-left: 10px;
                           " 
                           href="https://t.me/ondagames_links" 
                           target="_blank">
                            GRUPO TELEGRAM
                        </a>
                    </div>
                ')),
            Section::make('ALTERE LOGOTIPO E DADOS')
                ->description('Altere o logotipo e os dados da plataforma')
                ->schema([
                    Group::make()
                        ->columns(2)
                        ->schema([
                            TextInput::make('software_name')
                                ->label('NOME DA PLATAFORMA')
                                ->required()
                                ->maxLength(191),
                            TextInput::make('url_env')
                                ->label('URL DO PAINEL ADMIN')
                                ->required()
                                ->maxLength(191),
                        ]),
                    Group::make()
                        ->columns(2)
                        ->schema([
                            FileUpload::make('software_favicon')
                                ->label('FAVICON (até 1024×1024)')
                                ->image(),
                            Group::make()
                                ->columnSpan('full')
                                ->schema([
                                    FileUpload::make('software_logo_white')
                                        ->label('LOGOTIPO BRANCO (1228×274)')
                                        ->image(),
                                    FileUpload::make('software_logo_black')
                                        ->label('LOGOTIPO PRETO (1228×274)')
                                        ->image(),
                                ]),
                        ]),
                ]),

            Section::make('SEO BÁSICO')
                ->schema([
                    Textarea::make('meta_description')
                        ->label('Meta Description')
                        ->rows(3)
                        ->maxLength(65535),
                    TextInput::make('meta_keywords')
                        ->label('Meta Keywords')
                        ->helperText('Separe as palavras-chave por vírgula')
                        ->maxLength(255),
                ])
                ->columns(1),

            Section::make('Open Graph (Facebook/WhatsApp)')
                ->schema([
                    TextInput::make('og_title')
                        ->label('OG Title')
                        ->maxLength(255),
                    Textarea::make('og_description')
                        ->label('OG Description')
                        ->rows(3)
                        ->maxLength(65535),
                ])
                ->columns(2),

            Section::make('Twitter Card')
                ->schema([
                    TextInput::make('twitter_title')
                        ->label('Twitter Title')
                        ->maxLength(255),
                    Textarea::make('twitter_description')
                        ->label('Twitter Description')
                        ->rows(3)
                        ->maxLength(65535),
                ])
                ->columns(2),

            Section::make('Configurações Avançadas')
                ->schema([
                    Toggle::make('allow_indexing')
                        ->label('Permitir Indexação (no google, etc.)')
                        ->helperText('Desmarque para nao deixar o site indexado por mecanismos de busca'),
                    TextInput::make('site_url')
                        ->label('URL Base do Site (Canonical)')
                        ->url()
                        ->maxLength(255),
                ])
                ->columns(2),
        ])
        ->statePath('data');
    }

    /**
     * @dev  
     * @param $array
     * @return mixed|void
     */
    private function uploadFile($array)
    {
        if (!is_array($array) && !is_object($array)) {
            // Retorna a string diretamente, pois não é um arquivo para upload
            return $array;
        }
    
        if(!empty($array)) {
            foreach ($array as $k => $temporaryFile) {
                if ($temporaryFile instanceof TemporaryUploadedFile) {
                    $path = \Helper::upload($temporaryFile);
                    if($path) {
                        return $path['path'];
                    }
                } else {
                    return $temporaryFile;
                }
            }
        }
    }
}
