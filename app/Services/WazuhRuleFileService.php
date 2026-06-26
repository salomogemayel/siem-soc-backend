<?php

namespace App\Services;

use RuntimeException;

class WazuhRuleFileService
{
    private string $rulesFilePath;

    public function __construct()
    {
        $this->rulesFilePath = config('wazuh.rules_file_path');
    }

    public function getRulesFilePath(): string
    {
        return $this->rulesFilePath;
    }

    public function ensureRulesFileIsReadable(): void
    {
        if (!file_exists($this->rulesFilePath)) {
            throw new RuntimeException('Wazuh local_rules.xml file not found.');
        }

        if (!is_readable($this->rulesFilePath)) {
            throw new RuntimeException('Wazuh local_rules.xml file is not readable.');
        }
    }

    public function readContent(): string
    {
        $this->ensureRulesFileIsReadable();

        $content = file_get_contents($this->rulesFilePath);

        if ($content === false) {
            throw new RuntimeException('Failed to read Wazuh local_rules.xml file.');
        }

        return $content;
    }
}
