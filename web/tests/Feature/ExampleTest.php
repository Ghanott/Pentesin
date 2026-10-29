<?php

namespace Tests\Feature;

use Tests\TestCase;

class ExampleTest extends TestCase
{
    public function test_login_page_is_available_without_an_operator_session(): void
    {
        $this->get('/login')->assertOk()->assertSee('Masuk ke Akun');
    }
}
