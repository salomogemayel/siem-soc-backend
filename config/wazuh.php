<?php

return [
    'indexer_url' => env('WAZUH_INDEXER_URL'),
    'indexer_username' => env('WAZUH_INDEXER_USERNAME'),
    'indexer_password' => env('WAZUH_INDEXER_PASSWORD'),

    'indexes' => [
        'alerts' => 'wazuh-alerts-*',
        'archives' => 'wazuh-archives-*',
    ],

    'time_ranges' => [
        '15m',
        '30m',
        '1h',
        '6h',
        '24h',
        '7d',
        '30d',
    ],

    'rules_file_path' => env('WAZUH_RULES_FILE_PATH', '/var/ossec/etc/rules/local_rules.xml'),
];
