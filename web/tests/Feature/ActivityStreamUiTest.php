<?php

namespace Tests\Feature;

use PHPUnit\Framework\TestCase;

class ActivityStreamUiTest extends TestCase
{
    public function test_activity_stream_formats_only_tool_arguments_and_enter_key_contract_is_present(): void
    {
        $script = file_get_contents(dirname(__DIR__, 2).'/resources/js/agent-graph.js');
        self::assertIsString($script);
        self::assertStringContainsString("if (event.type === 'tool')", $script);
        self::assertStringContainsString('body = args?.cmd ?? args?.command', $script);
        self::assertStringContainsString("make('details', 'command-output')", $script);
        self::assertStringContainsString('previous.replaceWith(item)', $script);
        self::assertStringContainsString("event.key === 'Enter' && !event.shiftKey", $script);
        self::assertStringNotContainsString("make('pre', '', typeof data === 'string' ? data : text(data.content ?? data.text ?? data))", $script);
    }
}
