<?php

namespace App\Livewire;

use App\Models\LlmProfile;
use Illuminate\Contracts\View\View;
use Livewire\Component;

class ScanForm extends Component
{
    public function render(): View
    {
        return view('livewire.scan-form', [
            'profiles' => LlmProfile::query()->select('id', 'name', 'model')->where('user_id', auth()->id())->orderBy('name')->get(),
        ]);
    }
}
