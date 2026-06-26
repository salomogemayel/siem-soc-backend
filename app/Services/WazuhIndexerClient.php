<?php

namespace App\Services;

use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\Http;

class WazuhIndexerClient
{
    private string $indexerUrl;
    private string $username;
    private string $password;

    public function __construct()
    {
        $this->indexerUrl = rtrim(config('wazuh.indexer_url'), '/');
        $this->username = config('wazuh.indexer_username');
        $this->password = config('wazuh.indexer_password');
    }

    public function get(string $path = ''): Response
    {
        return Http::withBasicAuth($this->username, $this->password)
            ->withoutVerifying()
            ->get($this->indexerUrl . $path);
    }

    public function post(string $path, array $payload): Response
    {
        return Http::withBasicAuth($this->username, $this->password)
            ->withoutVerifying()
            ->post($this->indexerUrl . $path, $payload);
    }
}
