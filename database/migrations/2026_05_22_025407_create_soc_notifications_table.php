<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('soc_notifications', function (Blueprint $table) {
            $table->id();

            $table->string('source_alert_id')->unique();
            $table->string('type')->default('critical_alert');

            $table->string('title');
            $table->text('message')->nullable();

            $table->string('severity')->default('high');
            $table->string('rule_id')->nullable();
            $table->integer('rule_level')->nullable();

            $table->string('agent_id')->nullable();
            $table->string('agent_name')->nullable();

            $table->timestamp('alert_timestamp')->nullable();

            $table->boolean('is_read')->default(false);
            $table->timestamp('read_at')->nullable();

            $table->json('metadata')->nullable();

            $table->timestamps();

            $table->index(['is_read', 'created_at']);
            $table->index(['severity', 'created_at']);
            $table->index(['rule_id', 'created_at']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('soc_notifications');
    }
};
