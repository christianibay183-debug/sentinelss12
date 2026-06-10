<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Blacklist — Sentinels</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Special+Elite&display=swap" rel="stylesheet">
  <link href="https://db.onlinewebfonts.com/c/de54e55696de4441e90e41503b87bbf0?family=Migration+Sans+ITC+W01+Bold" rel="stylesheet">
  <link rel="stylesheet" href="../css/restricteds.css">
  <meta name="csrf-token" content="{{ session['csrf_token'] }}">
</head>
<body>

<div class="scanlines"></div>
<div class="vignette"></div>

<!-- SIDEBAR -->
<div class="sidebar">
  <div class="logo-area">
    <img src="../icons/logo.png" class="sidebar-logo" alt="Sentinels">
    <div class="sidebar-title">SENTINELS</div>
    <div class="sidebar-subtitle">SURVEILLANCE SYSTEM</div>
  </div>
  <nav class="nav">
    <a href="#" class="nav-item active"><span>▣</span> DASHBOARD</a>
        {% if user == 'admin' %}
        <a href="/logs" class="nav-item"><span>☰</span> LOGS</a>
        <a href="#" class="nav-item" id="settingsNavBtn"><span>⚙</span> SETTINGS</a>
        <a href="/restricteds" class="nav-item" id="settingsNavBtn"><span>⚙</span> RESTRICTEDS</a>
        {% endif %}
  </nav>
  <div class="sidebar-footer">
    <div class="user">● {{ user|upper }}</div>
    <button class="logout-btn" onclick="window.location='/logout'">SIGN OUT</button>
  </div>
</div>

<!-- MAIN -->
<div class="main">
  <div class="topbar">
    <h2>BLACKLIST MANAGEMENT</h2>
    <div class="topbar-right">
      <div class="live-status">
        <div class="live-dot"></div>
        <span>LIVE</span>
      </div>
      <span id="clock">--:--:--</span>
      <span id="date-str">----</span>
    </div>
  </div>

  <div class="blacklist-content">

    <!-- STATS -->
    <div class="bl-stats">
      <div class="bl-stat-card">
        <div class="bl-stat-number red">{{ blacklisted_ips | length }}</div>
        <div class="bl-stat-label">BLOCKED IPs</div>
      </div>
      <div class="bl-stat-card">
        <div class="bl-stat-number green">ACTIVE</div>
        <div class="bl-stat-label">FILTER STATUS</div>
      </div>
      <div class="bl-stat-card">
        <div class="bl-stat-number blue">AUTO</div>
        <div class="bl-stat-label">BLOCK MODE</div>
      </div>
    </div>

    <!-- ADD IP FORM -->
    <form method="POST" action="/admin/add_ip" class="bl-toolbar">
      <input type="hidden" name="csrf_token" value="{{ session['csrf_token'] }}">
      <input type="text" name="ip" class="bl-input" placeholder="ENTER IP ADDRESS TO BLOCK">
      <button type="submit" class="btn-add">+ ADD IP</button>
    </form>

    <!-- TABLE -->
    <div class="bl-table-card">
      <div class="bl-table-header">
        <span>IP ADDRESS</span>
        <span style="text-align:center;">ACTION</span>
      </div>
      <div class="bl-table-body">
        {% for ip in blacklisted_ips %}
        <div class="bl-row">
          <span class="ip-text">{{ ip }}</span>
          <form method="POST" action="/admin/remove_ip" style="display:flex; justify-content:center;">
            <input type="hidden" name="csrf_token" value="{{ session['csrf_token'] }}">
            <input type="hidden" name="ip" value="{{ ip }}">
            <button type="submit" class="btn-remove">UNBLOCK</button>
          </form>
        </div>
        {% else %}
        <div class="empty-row">NO BLACKLISTED IP ADDRESSES</div>
        {% endfor %}
      </div>
    </div>

  </div>
</div>

<script src="../js/restricteds.js"></script>
</body>
</html>