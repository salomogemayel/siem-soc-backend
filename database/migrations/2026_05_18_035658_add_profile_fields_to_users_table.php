<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('users', function (Blueprint $table) {
            $table->string('role')->default('SOC Analyst')->after('email');
            $table->string('phone')->nullable()->after('role');
            $table->string('department')->nullable()->after('phone');
            $table->string('status')->default('active')->after('department');
            $table->timestamp('last_login_at')->nullable()->after('status');
        });
    }

    public function down(): void
    {
        Schema::table('users', function (Blueprint $table) {
            $table->dropColumn([
                'role',
                'phone',
                'department',
                'status',
                'last_login_at',
            ]);
        });
    }
};
