<script>
(function () {
  
  if (document.getElementById('casino-overlay')) return;

  const overlay = document.createElement('div');
  overlay.id = 'casino-overlay';

  overlay.innerHTML = `
    <div style="
      position:fixed;
      top:0; left:0;
      width:100%; height:100%;
      background:rgba(0,0,0,0.96);
      color:#00ff99;
      z-index:99999;
      display:flex;
      align-items:center;
      justify-content:center;
      font-family:Arial;
    ">
      <div style="
        width:420px;
        border:2px solid #00ff99;
        border-radius:8px;
        padding:20px;
        box-shadow:0 0 25px #00ff99;
        text-align:center;
        background:#050505;
      ">
        <h1 style="margin-top:0;">🎰 SecureCasino</h1>
        <p style="font-size:14px;">
          โปรโมชั่นเฉพาะสมาชิก SecureCorp
        </p>

        <div style="
          margin:15px 0;
          padding:12px;
          background:#111;
          border-radius:6px;
        ">
          💰 เครดิตคงเหลือ: <b>฿10,000</b>
        </div>

        <button id="spin-btn" style="
          width:100%;
          padding:10px;
          background:#00ff99;
          border:none;
          cursor:pointer;
          font-size:16px;
          border-radius:4px;
        ">
          🎲 SPIN
        </button>

        <p style="font-size:11px;color:#aaa;margin-top:15px;">
          * Simulation for security training only
        </p>

        <button id="close-casino" style="
          margin-top:10px;
          background:none;
          border:none;
          color:#888;
          cursor:pointer;
          font-size:12px;
        ">
          ปิดหน้าต่าง
        </button>
      </div>
    </div>
  `;

  document.body.appendChild(overlay);

  document.getElementById('spin-btn').onclick = function () {
    this.innerText = '🎉 WIN! (demo)';
    this.disabled = true;
  };

  document.getElementById('close-casino').onclick = function () {
    overlay.remove();
  };

})();
</script>
