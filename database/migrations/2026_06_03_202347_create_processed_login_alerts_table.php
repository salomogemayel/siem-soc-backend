<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('processed_login_alerts', function (Blueprint $table) {
            $table->id();
            $table->string('wazuh_alert_id')->unique();
            $table->string('wazuh_rule_id')->nullable();
            $table->string('cis_user_id');
            $table->string('ip_address', 45);
            $table->timestamp('processed_at')->nullable();
            $table->timestamps();
            $table->index(['cis_user_id', 'ip_address']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('processed_login_alerts');
    }
};
