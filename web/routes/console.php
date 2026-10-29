<?php

use App\Models\User;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Hash;

Artisan::command('pentesin:operator {email}', function (string $email): int {
    $name = $this->ask('Nama operator');
    $password = $this->secret('Password operator');
    if (! is_string($password) || strlen($password) < 16) {
        $this->error('Password harus minimal 16 karakter.');

        return self::FAILURE;
    }
    User::updateOrCreate(['email' => $email], ['name' => $name, 'password' => Hash::make($password)]);
    $this->info('Akun operator tersimpan.');

    return self::SUCCESS;
})->purpose('Buat atau rotasi akun operator privat Pentesin');
