<?php

namespace Database\Seeders;

use App\Models\User;
use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;

class DatabaseSeeder extends Seeder
{
    use WithoutModelEvents;

    /**
     * Seed the application's database.
     */
    public function run(): void
    {
        if (app()->environment('production')) {
            throw new \RuntimeException('Refusing to seed default users in production. Create the operator with pentesin:operator.');
        }

        if (app()->environment('local', 'testing')) {
            User::updateOrCreate(
                ['email' => 'a@a'],
                ['name' => 'Operator Lokal', 'password' => 'a'],
            );
        }
    }
}
