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

            $table->foreignId('user_id')
                ->constrained()
                ->cascadeOnDelete();

            $table->string('source_alert_id');
            $table->string('type')->default('critical_alert');

            $table->string('title');
            $table->text('message')->nullable();

            $table->string('severity')->default('high');
            $table->string('rule_id')->nullable();
            $table->integer('rule_level')->nullable();

            $table->string('agent_id')->nullable();
            $table->string('agent_name')->nullable();

            $table->string('alert_timestamp')->nullable();

            $table->boolean('is_read')->default(false);
            $table->timestamp('read_at')->nullable();

            $table->json('metadata')->nullable();

            $table->timestamps();

            $table->unique(['user_id', 'source_alert_id']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('soc_notifications');
    }
};
