<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('user_ip_baselines', function (Blueprint $table) {
            $table->id();
            $table->string('cis_user_id');
            $table->string('ip_address', 45);
            $table->string('device')->default('UNKNOWN'); // Tambahan
            $table->timestamp('first_seen_at')->nullable();
            $table->timestamp('last_seen_at')->nullable();
            $table->unsignedInteger('login_count')->default(1);
            $table->boolean('is_trusted')->default(false);
            $table->timestamps();

            $table->unique(['cis_user_id', 'ip_address', 'device'], 'user_ip_device_unique');
        });
    }
    public function down(): void
    {
        Schema::dropIfExists('user_ip_baselines');
    }
};
