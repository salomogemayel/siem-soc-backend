<?php

namespace App\Services;

use Illuminate\Support\Facades\Http;

class WazuhApiService
{
    protected $apiUrl;
    protected $username;
    protected $password;
    protected $token;

    public function __construct()
    {
        $this->apiUrl = env('WAZUH_API_URL');
        $this->username = env('WAZUH_API_USERNAME');
        $this->password = env('WAZUH_API_PASSWORD');

        $this->token = $this->authenticate();
    }

    private function authenticate()
    {
        try {
            $response = Http::withBasicAuth($this->username, $this->password)
                ->withoutVerifying()
                ->post($this->apiUrl . '/security/user/authenticate?raw=true');

            if ($response->successful()) {
                return $response->body();
            }

            return null;

        } catch (\Exception $e) {
            return null;
        }
    }

    private function request($method, $endpoint, $query = [])
    {
        return Http::withToken($this->token)
            ->withoutVerifying()
            ->$method($this->apiUrl . $endpoint, $query);
    }

    public function getRules($page = 1, $size = 20, $search = '', $level = '', $group = '')
    {
        try {
            $offset = ($page - 1) * $size;

            $query = [
                'offset' => $offset,
                'limit' => $size,
                'sort' => '+id',
            ];

            if ($search) {
                $query['search'] = $search;
            }

            if ($level) {
                $query['level'] = (int)$level . '-16';
            }

            if ($group) {
                $query['group'] = $group;
            }

            $response = $this->request('get', '/rules', $query);

            if (!$response->successful()) {
                return [
                    'success' => false,
                    'error' => $response->body()
                ];
            }

            return [
                'success' => true,
                'data' => $response->json()['data']
            ];

        } catch (\Exception $e) {
            return [
                'success' => false,
                'error' => $e->getMessage()
            ];
        }
    }

    public function getAgents($page = 1, $size = 20, $search = '', $status = '')
    {
        try {
            $offset = ($page - 1) * $size;

            $query = [
                'offset' => $offset,
                'limit' => $size,
                'sort' => '+id',
            ];

            if ($search) {
                $query['search'] = $search;
            }

            if ($status) {
                $query['status'] = $status;
            }

            $response = $this->request('get', '/agents', $query);

            if (!$response->successful()) {
                return [
                    'success' => false,
                    'error' => $response->body()
                ];
            }

            return [
                'success' => true,
                'data' => $response->json()['data']
            ];

        } catch (\Exception $e) {
            return [
                'success' => false,
                'error' => $e->getMessage()
            ];
        }
    }

    public function getManagerInfo()
    {
        try {
            $statusResponse = $this->request('get', '/manager/status');
            $infoResponse = $this->request('get', '/manager/info');

            if (!$statusResponse->successful() || !$infoResponse->successful()) {
                return [
                    'success' => false,
                    'error' => [
                        'status_error' => $statusResponse->body(),
                        'info_error' => $infoResponse->body(),
                    ],
                ];
            }

            return [
                'success' => true,
                'data' => [
                    'status' => $statusResponse->json()['data'] ?? [],
                    'info' => $infoResponse->json()['data'] ?? [],
                ],
            ];

        } catch (\Exception $e) {
            return [
                'success' => false,
                'error' => $e->getMessage(),
            ];
        }
    }

    public function getAgentsHealthSummary()
    {
        try {
            return [
                'total_agents' => $this->getAgentCount(),
                'active_agents' => $this->getAgentCount('active'),
                'disconnected_agents' => $this->getAgentCount('disconnected'),
                'never_connected_agents' => $this->getAgentCount('never_connected'),
            ];

        } catch (\Exception $e) {
            return [
                'total_agents' => 0,
                'active_agents' => 0,
                'disconnected_agents' => 0,
                'never_connected_agents' => 0,
            ];
        }
    }

    private function getAgentCount($status = null)
    {
        $query = [
            'limit' => 1,
        ];

        if ($status) {
            $query['status'] = $status;
        }

        $response = $this->request('get', '/agents', $query);

        if (!$response->successful()) {
            return 0;
        }

        return $response->json()['data']['total_affected_items'] ?? 0;
    }
}
