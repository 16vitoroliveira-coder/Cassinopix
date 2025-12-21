<x-filament::page>
    <div class="space-y-6">
        {{ $this->form }}
        <x-filament::button type="submit" form="submit">
            Atualizar dados
        </x-filament::button>
        <x-filament::section>
            <h2 class="text-xl font-bold">Configuração</h2>

            {{ $this->table }}
        </x-filament::section>
    </div>
</x-filament::page>
