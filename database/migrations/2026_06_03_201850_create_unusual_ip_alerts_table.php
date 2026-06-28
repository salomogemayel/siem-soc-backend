<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('unusual_ip_alerts', function (Blueprint $table) {
            $table->id();
            $table->string('cis_user_id');
            $table->string('ip_address', 45);
            $table->string('device')->nullable();
            $table->string('wazuh_alert_id')->nullable();
            $table->string('wazuh_rule_id')->nullable();
            $table->timestamp('detected_at')->nullable();
            $table->string('reason')->default('New IP address or Device for this CIS user');
            $table->enum('status', ['new', 'reviewed', 'false_positive'])->default('new');
            $table->timestamps();

            $table->index(['cis_user_id', 'ip_address', 'device']);
            $table->index('status');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('unusual_ip_alerts');
    }
};
