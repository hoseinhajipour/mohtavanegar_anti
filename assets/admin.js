(function ($) {
  'use strict';

  if (typeof MVN === 'undefined') {
    return;
  }

  function post(action, data) {
    data = data || {};
    data.action = action;
    data.nonce = MVN.nonce;
    return $.ajax({
      url: MVN.ajax,
      method: 'POST',
      dataType: 'json',
      data: data,
    });
  }

  function pct(done, total) {
    if (!total) return 0;
    return Math.min(100, Math.round((done / total) * 100));
  }

  function notice($el, msg, ok) {
    $el.html(
      '<div class="mvn-notice ' +
        (ok ? 'mvn-notice-ok' : 'mvn-notice-err') +
        '">' +
        $('<div>').text(msg).html() +
        '</div>'
    );
  }

  function scanStatsText(s) {
    var st = s.stats || {};
    var parts = [
      'بحرانی: ' + (st.critical || 0),
      'هشدار: ' + (st.warning || 0),
      'htaccess: ' + (st.htaccess || 0),
      'PHP: ' + (st.php || 0),
    ];
    if (s.incremental && (s.skipped_unchanged || s.catalog)) {
      parts.push('ردشده (بدون تغییر): ' + (s.skipped_unchanged || 0));
      if (s.catalog) {
        parts.push('کاتالوگ: ' + s.catalog);
      }
    }
    if (s.stats && s.stats.db) {
      parts.push('DB: ' + s.stats.db);
    }
    if (s.stats && s.stats.core) {
      parts.push('Core: ' + s.stats.core);
    }
    return parts.join(' | ');
  }

  function scanPhaseLabel(s) {
    if (s.phase === 'core') {
      var extra = s.core_version ? ' (WP ' + s.core_version + ')' : '';
      return 'checksum هسته' + extra;
    }
    if (s.phase === 'db') {
      return 'دیتابیس — ' + (s.db_phase_label || s.db_phase || '...');
    }
    return 'فایل‌ها';
  }

  /* ---------- Scan ---------- */
  var scanTimer = null;
  var scanBusy = false;

  function clearScanTimer() {
    if (scanTimer) {
      clearTimeout(scanTimer);
      scanTimer = null;
    }
  }

  function setScanControls(status) {
    var running = status === 'running';
    var paused = status === 'paused';
    var active = running || paused;
    $('#mvn-scan-start').prop('disabled', active);
    $('#mvn-scan-scope, #mvn-scan-deep, #mvn-scan-core, #mvn-scan-db, #mvn-scan-incremental, #mvn-scan-full').prop('disabled', active);
    $('#mvn-scan-pause').toggle(running);
    $('#mvn-scan-resume').toggle(paused);
    $('#mvn-scan-stop').toggle(active);
    if (active) {
      $('#mvn-scan-progress').show();
    }
  }

  function renderScanProgress(s) {
    var p = pct(s.processed, s.total);
    $('#mvn-scan-bar').css('width', p + '%');
    $('#mvn-scan-pct').text(p + '%');
    var label = scanPhaseLabel(s) + ' — بررسی‌شده: ' + s.processed + ' / ' + s.total + ' — یافته‌ها: ' + s.issue_count;
    if (s.status === 'paused') {
      label = '⏸ متوقف موقت — ' + label;
    }
    if (s.incremental && s.skipped_unchanged) {
      label += ' — ردشده: ' + s.skipped_unchanged;
    }
    $('#mvn-scan-label').text(label);
    $('#mvn-scan-stats').text(scanStatsText(s));
  }

  function finishScanUi(s) {
    clearScanTimer();
    scanBusy = false;
    setScanControls(s.status || 'idle');
    if (s.status === 'done') {
      $('#mvn-scan-label').text(MVN.i18n.done);
      var html =
        '<div class="mvn-notice mvn-notice-ok">اسکن تمام شد. تعداد مشکلات: <b>' +
        s.issue_count +
        '</b>';
      if (s.incremental && s.skipped_unchanged) {
        html += ' — ردشده (بدون تغییر): <b>' + s.skipped_unchanged + '</b>';
      }
      html += '. ';
      if (s.issue_count > 0) {
        html += '<a href="admin.php?page=mvn-fix">رفتن به صفحه رفع مشکلات</a>';
      }
      html += '</div>';
      $('#mvn-scan-result').show().html(html);
    } else if (s.status === 'stopped') {
      $('#mvn-scan-label').text(MVN.i18n.stopped || 'اسکن متوقف شد');
      var htmlStop =
        '<div class="mvn-notice mvn-notice-err">اسکن متوقف شد. یافته‌های فعلی: <b>' +
        s.issue_count +
        '</b>. ';
      if (s.issue_count > 0) {
        htmlStop += '<a href="admin.php?page=mvn-fix">رفتن به صفحه رفع مشکلات</a>';
      }
      htmlStop += '</div>';
      $('#mvn-scan-result').show().html(htmlStop);
    } else if (s.status === 'paused') {
      $('#mvn-scan-label').text(MVN.i18n.paused || 'اسکن متوقف موقت شد');
      notice(
        $('#mvn-scan-result').show(),
        (MVN.i18n.paused || 'اسکن متوقف موقت شد') +
          ' — بررسی‌شده: ' +
          s.processed +
          '/' +
          s.total +
          ' — یافته‌ها: ' +
          s.issue_count,
        true
      );
    }
  }

  function scheduleScanTick() {
    clearScanTimer();
    scanTimer = setTimeout(runScanLoop, 80);
  }

  function runScanLoop() {
    if (scanBusy) return;
    scanBusy = true;
    post('mvn_scan_tick')
      .done(function (res) {
        scanBusy = false;
        if (!res || !res.success) {
          notice($('#mvn-scan-result').show(), (res && res.data && res.data.message) || MVN.i18n.error, false);
          setScanControls('idle');
          return;
        }
        var s = res.data;
        renderScanProgress(s);
        setScanControls(s.status);

        if (s.status === 'running') {
          scheduleScanTick();
        } else if (s.status === 'paused') {
          finishScanUi(s);
        } else if (s.status === 'done' || s.status === 'stopped') {
          finishScanUi(s);
        } else {
          notice($('#mvn-scan-result').show(), 'وضعیت نامشخص: ' + s.status, false);
          setScanControls('idle');
        }
      })
      .fail(function () {
        scanBusy = false;
        notice($('#mvn-scan-result').show(), 'خطای ارتباط با سرور', false);
        setScanControls('idle');
      });
  }

  $('#mvn-scan-full').on('change', function () {
    if ($(this).is(':checked')) {
      $('#mvn-scan-incremental').prop('checked', false);
    }
  });

  $('#mvn-scan-incremental').on('change', function () {
    if ($(this).is(':checked')) {
      $('#mvn-scan-full').prop('checked', false);
    }
  });

  $('#mvn-scan-start').on('click', function () {
    var $btn = $(this);
    $btn.prop('disabled', true);
    $('#mvn-scan-progress').show();
    $('#mvn-scan-result').hide().empty();
    $('#mvn-scan-bar').css('width', '0%');
    $('#mvn-scan-label').text(MVN.i18n.scanning);
    setScanControls('running');

    var full = $('#mvn-scan-full').is(':checked');
    post('mvn_scan_start', {
      scope: $('#mvn-scan-scope').val(),
      deep: $('#mvn-scan-deep').is(':checked') ? 1 : 0,
      incremental: full ? 0 : $('#mvn-scan-incremental').is(':checked') ? 1 : 0,
      full: full ? 1 : 0,
      scan_db: $('#mvn-scan-db').is(':checked') ? 1 : 0,
      scan_core: $('#mvn-scan-core').is(':checked') ? 1 : 0,
    })
      .done(function (res) {
        if (!res || !res.success) {
          notice($('#mvn-scan-result').show(), (res && res.data && res.data.message) || MVN.i18n.error, false);
          setScanControls('idle');
          return;
        }
        renderScanProgress(res.data);
        scheduleScanTick();
      })
      .fail(function () {
        notice($('#mvn-scan-result').show(), 'خطای ارتباط با سرور', false);
        setScanControls('idle');
      });
  });

  $('#mvn-scan-pause').on('click', function () {
    clearScanTimer();
    $(this).prop('disabled', true);
    post('mvn_scan_pause')
      .done(function (res) {
        $('#mvn-scan-pause').prop('disabled', false);
        if (!res || !res.success) {
          notice($('#mvn-scan-result').show(), (res && res.data && res.data.message) || MVN.i18n.error, false);
          scheduleScanTick();
          return;
        }
        renderScanProgress(res.data);
        finishScanUi(res.data);
      })
      .fail(function () {
        $('#mvn-scan-pause').prop('disabled', false);
        notice($('#mvn-scan-result').show(), 'خطای ارتباط با سرور', false);
        scheduleScanTick();
      });
  });

  $('#mvn-scan-resume').on('click', function () {
    $(this).prop('disabled', true);
    $('#mvn-scan-result').hide().empty();
    post('mvn_scan_resume')
      .done(function (res) {
        $('#mvn-scan-resume').prop('disabled', false);
        if (!res || !res.success) {
          notice($('#mvn-scan-result').show(), (res && res.data && res.data.message) || MVN.i18n.error, false);
          return;
        }
        renderScanProgress(res.data);
        setScanControls('running');
        scheduleScanTick();
      })
      .fail(function () {
        $('#mvn-scan-resume').prop('disabled', false);
        notice($('#mvn-scan-result').show(), 'خطای ارتباط با سرور', false);
      });
  });

  $('#mvn-scan-stop').on('click', function () {
    if (!window.confirm(MVN.i18n.confirm_stop || MVN.i18n.confirm)) return;
    clearScanTimer();
    $(this).prop('disabled', true);
    post('mvn_scan_stop')
      .done(function (res) {
        $('#mvn-scan-stop').prop('disabled', false);
        if (!res || !res.success) {
          notice($('#mvn-scan-result').show(), (res && res.data && res.data.message) || MVN.i18n.error, false);
          return;
        }
        renderScanProgress(res.data);
        finishScanUi(res.data);
      })
      .fail(function () {
        $('#mvn-scan-stop').prop('disabled', false);
        notice($('#mvn-scan-result').show(), 'خطای ارتباط با سرور', false);
      });
  });

  // Resume UI if page reloaded mid-scan.
  if (window.MVN_SCAN_BOOT && window.MVN_SCAN_BOOT.status === 'running') {
    setScanControls('running');
    scheduleScanTick();
  } else if (window.MVN_SCAN_BOOT && window.MVN_SCAN_BOOT.status === 'paused') {
    setScanControls('paused');
    post('mvn_scan_status').done(function (res) {
      if (res && res.success) {
        renderScanProgress(res.data);
        finishScanUi(res.data);
      }
    });
  }

  /* ---------- Ignore (mark safe) ---------- */
  $(document).on('click', '.mvn-ignore-one', function () {
    if (!window.confirm(MVN.i18n.confirm_ignore || MVN.i18n.confirm)) return;
    var $btn = $(this);
    var id = $btn.data('id');
    var $row = $btn.closest('tr');
    $btn.prop('disabled', true).text(MVN.i18n.ignoring || '...');
    post('mvn_fix_ignore', { id: id })
      .done(function (res) {
        if (res && res.success) {
          $row.fadeOut(200, function () {
            $(this).remove();
            if (!$('#mvn-issues-table tbody tr').length) {
              window.location.reload();
            }
          });
        } else {
          alert((res && res.data && res.data.message) || MVN.i18n.error);
          $btn.prop('disabled', false).text('امن است');
        }
      })
      .fail(function () {
        alert('خطای ارتباط');
        $btn.prop('disabled', false).text('امن است');
      });
  });

  /* ---------- Fix one ---------- */
  $(document).on('click', '.mvn-fix-one', function () {
    var $btn = $(this);
    var id = $btn.data('id');
    var $row = $btn.closest('tr');
    $btn.prop('disabled', true).text('...');
    post('mvn_fix_one', { id: id })
      .done(function (res) {
        if (res && res.success) {
          $row.fadeOut(200, function () {
            $(this).remove();
          });
        } else {
          alert((res && res.data && res.data.message) || MVN.i18n.error);
          $btn.prop('disabled', false).text('رفع');
        }
      })
      .fail(function () {
        alert('خطای ارتباط');
        $btn.prop('disabled', false).text('رفع');
      });
  });

  /* ---------- Fix batch ---------- */
  var fixBatchRunning = false;

  function setFixBatchButtonsDisabled(disabled) {
    $('.mvn-fix-batch').prop('disabled', disabled);
  }

  function runFixBatch(filter, totalHint) {
    if (fixBatchRunning) return;
    fixBatchRunning = true;
    $('#mvn-fix-progress').show();
    setFixBatchButtonsDisabled(true);

    post('mvn_fix_batch', { filter: filter || '' })
      .done(function (res) {
        if (!res || !res.success) {
          $('#mvn-fix-label').text((res && res.data && res.data.message) || MVN.i18n.error);
          fixBatchRunning = false;
          setFixBatchButtonsDisabled(false);
          return;
        }
        var r = res.data;
        var rem = r.remaining || 0;
        var doneTotal = totalHint ? totalHint - rem : r.fixed;
        var p = totalHint ? pct(Math.max(0, doneTotal), totalHint) : 50;
        $('#mvn-fix-bar').css('width', p + '%');
        var label =
          'رفع‌شده: ' + r.fixed + ' | ناموفق: ' + r.failed + ' | باقی‌مانده: ' + rem;
        if (r.errors && r.errors.length) {
          label += ' — ' + r.errors.slice(0, 3).join(' | ');
        }
        $('#mvn-fix-label').text(label);

        if (r.fixed > 0 && rem > 0) {
          setTimeout(function () {
            fixBatchRunning = false;
            runFixBatch(filter, totalHint);
          }, 100);
          return;
        }

        fixBatchRunning = false;

        if (r.fixed === 0 && r.failed === 0 && rem > 0 && filter) {
          $('#mvn-fix-label').text('موردی با این فیلتر برای رفع یافت نشد.');
          setFixBatchButtonsDisabled(false);
          return;
        }

        if (r.failed > 0 && rem > 0) {
          $('#mvn-fix-label').text(
            MVN.i18n.done + ' — برخی موارد ناموفق بودند. صفحه در حال تازه‌سازی...'
          );
        } else {
          $('#mvn-fix-label').text(MVN.i18n.done + ' — صفحه در حال تازه‌سازی...');
        }
        setTimeout(function () {
          window.location.reload();
        }, 800);
      })
      .fail(function () {
        $('#mvn-fix-label').text('خطای ارتباط');
        fixBatchRunning = false;
        setFixBatchButtonsDisabled(false);
      });
  }

  $('.mvn-fix-batch').on('click', function () {
    if ($(this).prop('disabled')) return;
    if (!window.confirm(MVN.i18n.confirm)) return;
    var filter = $(this).data('filter') || '';
    var total = filter ? parseInt($(this).text().match(/\((\d+)\)/)?.[1] || '0', 10) : parseInt(
      $('#mvn-fix-all').text().match(/\((\d+)\)/)?.[1] || $('#mvn-issues-table tbody tr').length,
      10
    );
    if (!total) {
      total = $('#mvn-issues-table tbody tr').length;
    }
    $('#mvn-fix-bar').css('width', '0%');
    runFixBatch(filter, total);
  });

  $('#mvn-fix-clear').on('click', function () {
    if (!window.confirm('لیست مشکلات فعلی پاک شود؟ (برای نتایج به‌روز، بعداً اسکن مجدد بزنید)')) return;
    post('mvn_fix_clear').done(function (res) {
      if (res && res.success) {
        window.location.reload();
      } else {
        alert((res && res.data && res.data.message) || MVN.i18n.error);
      }
    });
  });

  $('#mvn-scan-scope').on('change', function () {
    var isContentOnly = $(this).val() === 'wp-content';
    $('#mvn-scan-core').prop('disabled', isContentOnly);
    if (isContentOnly) {
      $('#mvn-scan-core').prop('checked', false);
    }
  });

  /* ---------- Core integrity (standalone) ---------- */
  function runIntegrityLoop() {
    post('mvn_core_integrity_tick')
      .done(function (res) {
        if (!res || !res.success) {
          notice($('#mvn-integrity-result'), (res && res.data && res.data.message) || MVN.i18n.error, false);
          $('#mvn-integrity-start').prop('disabled', false);
          return;
        }
        var s = res.data;
        var p = pct(s.processed, s.total);
        $('#mvn-integrity-bar').css('width', p + '%');
        $('#mvn-integrity-pct').text(p + '%');
        $('#mvn-integrity-label').text(
          (s.core_sub === 'extras' ? 'فایل‌های اضافی' : 'بررسی checksum') +
            ' — ' + s.processed + '/' + s.total +
            ' — یافته‌ها: ' + s.issue_count +
            (s.core_source ? ' [' + s.core_source + ']' : '')
        );
        if (s.status === 'running') {
          setTimeout(runIntegrityLoop, 80);
        } else if (s.status === 'done') {
          var msg = 'بررسی checksum تمام شد. مشکلات: <b>' + s.issue_count + '</b>';
          if (s.issue_count > 0) {
            msg += ' — <a href="admin.php?page=mvn-fix">رفتن به رفع مشکلات</a>';
          } else {
            msg += ' — هسته سالم است.';
          }
          notice($('#mvn-integrity-result'), msg, s.issue_count === 0);
          $('#mvn-integrity-start').prop('disabled', false);
          if (s.issue_count > 0) {
            setTimeout(function () { window.location.reload(); }, 1500);
          }
        }
      })
      .fail(function () {
        notice($('#mvn-integrity-result'), 'خطای ارتباط', false);
        $('#mvn-integrity-start').prop('disabled', false);
      });
  }

  $('#mvn-integrity-start').on('click', function () {
    var $btn = $(this);
    $btn.prop('disabled', true);
    $('#mvn-integrity-progress').show();
    $('#mvn-integrity-result').empty();
    $('#mvn-integrity-bar').css('width', '0%');
    post('mvn_core_integrity_start')
      .done(function (res) {
        if (!res || !res.success) {
          notice($('#mvn-integrity-result'), (res && res.data && res.data.message) || MVN.i18n.error, false);
          $btn.prop('disabled', false);
          return;
        }
        setTimeout(runIntegrityLoop, 50);
      })
      .fail(function () {
        notice($('#mvn-integrity-result'), 'خطای ارتباط', false);
        $btn.prop('disabled', false);
      });
  });

  /* ---------- Core repair ---------- */
  function runCoreLoop() {
    post('mvn_core_tick')
      .done(function (res) {
        if (!res || !res.success) {
          notice($('#mvn-core-result'), (res && res.data && res.data.message) || MVN.i18n.error, false);
          return;
        }
        var s = res.data;
        var p = pct(s.cursor, s.total);
        $('#mvn-core-bar').css('width', p + '%');
        $('#mvn-core-pct').text(p + '%');
        $('#mvn-core-label').text(
          'نوشته‌شده: ' + s.written + ' | ردشده (یکسان): ' + s.skipped + ' | ' + s.cursor + '/' + s.total
        );
        if (s.status === 'running') {
          setTimeout(runCoreLoop, 60);
        } else if (s.status === 'done') {
          var msg = 'تعمیر هسته تمام شد. نوشته‌شده: ' + s.written + '، ردشده: ' + s.skipped;
          if (s.errors && s.errors.length) {
            msg += ' — خطاها: ' + s.errors.join(' | ');
            notice($('#mvn-core-result'), msg, false);
          } else {
            notice($('#mvn-core-result'), msg, true);
          }
          $('#mvn-core-start').prop('disabled', false);
        } else {
          notice($('#mvn-core-result'), 'خطا در تعمیر', false);
          $('#mvn-core-start').prop('disabled', false);
        }
      })
      .fail(function () {
        notice($('#mvn-core-result'), 'خطای ارتباط', false);
        $('#mvn-core-start').prop('disabled', false);
      });
  }

  $('#mvn-core-start').on('click', function () {
    if (!window.confirm('فایل‌های هسته وردپرس از zip جایگزین می‌شوند. ادامه؟')) return;
    var $btn = $(this);
    $btn.prop('disabled', true);
    $('#mvn-core-progress').show();
    $('#mvn-core-result').empty();
    post('mvn_core_start')
      .done(function (res) {
        if (!res || !res.success) {
          notice($('#mvn-core-result'), (res && res.data && res.data.message) || MVN.i18n.error, false);
          $btn.prop('disabled', false);
          return;
        }
        setTimeout(runCoreLoop, 50);
      })
      .fail(function () {
        notice($('#mvn-core-result'), 'خطای ارتباط', false);
        $btn.prop('disabled', false);
      });
  });

  /* ---------- Plugin repair (WordPress.org) ---------- */
  var pluginRepairSlug = '';

  function runPluginLoop() {
    post('mvn_plugin_tick')
      .done(function (res) {
        if (!res || !res.success) {
          notice($('#mvn-plugin-result'), (res && res.data && res.data.message) || MVN.i18n.error, false);
          $('.mvn-plugin-repair').prop('disabled', false);
          return;
        }
        var s = res.data;
        var p = pct(s.cursor, s.total);
        $('#mvn-plugin-bar').css('width', p + '%');
        $('#mvn-plugin-pct').text(p + '%');
        $('#mvn-plugin-label').text(
          (s.name || s.slug) + ' — نوشته‌شده: ' + s.written + ' | ' + s.cursor + '/' + s.total
        );
        if (s.status === 'running') {
          setTimeout(runPluginLoop, 80);
        } else if (s.status === 'done') {
          var msg = 'تعمیر «' + (s.name || s.slug) + '» تمام شد. نوشته‌شده: ' + s.written;
          if (s.skipped) msg += ' | ردشده (یکسان): ' + s.skipped;
          if (s.errors && s.errors.length) {
            msg += ' — خطاها: ' + s.errors.join(' | ');
            notice($('#mvn-plugin-result'), msg, false);
          } else {
            notice($('#mvn-plugin-result'), msg, true);
          }
          $('.mvn-plugin-repair').prop('disabled', false);
          setTimeout(function () { window.location.reload(); }, 1200);
        } else {
          notice($('#mvn-plugin-result'), 'خطا در تعمیر پلاگین', false);
          $('.mvn-plugin-repair').prop('disabled', false);
        }
      })
      .fail(function () {
        notice($('#mvn-plugin-result'), 'خطای ارتباط', false);
        $('.mvn-plugin-repair').prop('disabled', false);
      });
  }

  $(document).on('click', '.mvn-plugin-repair', function () {
    var slug = $(this).data('slug');
    var name = $(this).data('name') || slug;
    if (!slug) return;
    if (
      !window.confirm(
        'پلاگین «' + name + '» از مخزن wordpress.org دانلود و جایگزین شود؟\nنسخه فعلی قبل از جایگزینی پشتیبان‌گیری می‌شود.'
      )
    ) {
      return;
    }
    pluginRepairSlug = slug;
    $('.mvn-plugin-repair').prop('disabled', true);
    $('#mvn-plugin-progress').show();
    $('#mvn-plugin-result').empty();
    $('#mvn-plugin-bar').css('width', '0%');
    $('#mvn-plugin-label').text('در حال دانلود از wordpress.org...');

    post('mvn_plugin_start', { slug: slug })
      .done(function (res) {
        if (!res || !res.success) {
          notice($('#mvn-plugin-result'), (res && res.data && res.data.message) || MVN.i18n.error, false);
          $('.mvn-plugin-repair').prop('disabled', false);
          return;
        }
        setTimeout(runPluginLoop, 50);
      })
      .fail(function () {
        notice($('#mvn-plugin-result'), 'خطای ارتباط (دانلود ممکن است طول بکشد)', false);
        $('.mvn-plugin-repair').prop('disabled', false);
      });
  });

  /* ---------- Permissions ---------- */
  function runPermsLoop() {
    post('mvn_perms_tick')
      .done(function (res) {
        if (!res || !res.success) {
          notice($('#mvn-perms-result'), (res && res.data && res.data.message) || MVN.i18n.error, false);
          return;
        }
        var s = res.data;
        var p = pct(s.cursor, s.total);
        $('#mvn-perms-bar').css('width', p + '%');
        $('#mvn-perms-pct').text(p + '%');
        $('#mvn-perms-label').text('اصلاح‌شده: ' + s.fixed + ' | ' + s.cursor + '/' + s.total);
        if (s.status === 'running') {
          setTimeout(runPermsLoop, 50);
        } else {
          notice($('#mvn-perms-result'), 'تمام شد. تعداد اصلاح‌شده: ' + s.fixed, true);
          $('#mvn-perms-start').prop('disabled', false);
        }
      })
      .fail(function () {
        notice($('#mvn-perms-result'), 'خطای ارتباط', false);
        $('#mvn-perms-start').prop('disabled', false);
      });
  }

  $('#mvn-perms-start').on('click', function () {
    var $btn = $(this);
    $btn.prop('disabled', true);
    $('#mvn-perms-progress').show();
    $('#mvn-perms-result').empty();
    post('mvn_perms_start')
      .done(function (res) {
        if (!res || !res.success) {
          notice($('#mvn-perms-result'), (res && res.data && res.data.message) || MVN.i18n.error, false);
          $btn.prop('disabled', false);
          return;
        }
        setTimeout(runPermsLoop, 50);
      })
      .fail(function () {
        notice($('#mvn-perms-result'), 'خطای ارتباط', false);
        $btn.prop('disabled', false);
      });
  });

  /* ---------- Htaccess ---------- */
  $('#mvn-ht-restore').on('click', function () {
    if (!window.confirm('htaccess ریشه با نسخه پیش‌فرض پلاگین جایگزین شود؟')) return;
    var $btn = $(this);
    $btn.prop('disabled', true);
    post('mvn_htaccess_restore')
      .done(function (res) {
        if (res && res.success) {
          notice($('#mvn-ht-restore-result'), res.data.message, true);
        } else {
          notice($('#mvn-ht-restore-result'), (res && res.data && res.data.message) || MVN.i18n.error, false);
        }
      })
      .always(function () {
        $btn.prop('disabled', false);
      });
  });

  $('#mvn-ht-purge').on('click', function () {
    if (!window.confirm('htaccess های جعلی حذف شوند؟ (نسخه در قرنطینه ذخیره می‌شود)')) return;
    var $btn = $(this);
    $btn.prop('disabled', true);
    post('mvn_htaccess_purge', {
      aggressive: $('#mvn-ht-aggressive').is(':checked') ? 1 : 0,
    })
      .done(function (res) {
        if (res && res.success) {
          var r = res.data;
          notice(
            $('#mvn-ht-purge-result'),
            'حذف‌شده: ' + r.deleted + ' | ردشده: ' + r.skipped + (r.errors && r.errors.length ? ' | خطا: ' + r.errors.join(', ') : ''),
            !r.errors || !r.errors.length
          );
        } else {
          notice($('#mvn-ht-purge-result'), (res && res.data && res.data.message) || MVN.i18n.error, false);
        }
      })
      .always(function () {
        $btn.prop('disabled', false);
      });
  });

  /* ---------- Hardening ---------- */
  $('#mvn-hardening-form').on('submit', function (e) {
    e.preventDefault();
    var data = $(this).serializeArray();
    var payload = { settings: {} };
    // Unchecked checkboxes won't appear — start from zeros for known keys.
    var keys = [
      'block_xmlrpc',
      'login_brute_force',
      'disable_file_edit',
      'disable_file_mods',
      'hide_wp_version',
      'block_user_enum',
      'disable_app_passwords',
      'remove_really_simple',
      'secure_headers',
      'login_max_attempts',
      'login_lockout_minutes',
    ];
    keys.forEach(function (k) {
      payload.settings[k] = 0;
    });
    data.forEach(function (item) {
      var m = item.name.match(/^settings\[(.+)\]$/);
      if (m) {
        payload.settings[m[1]] = item.value;
      }
    });
    post('mvn_hardening_save', payload)
      .done(function (res) {
        if (res && res.success) {
          notice($('#mvn-hardening-result'), res.data.message, true);
        } else {
          notice($('#mvn-hardening-result'), (res && res.data && res.data.message) || MVN.i18n.error, false);
        }
      })
      .fail(function () {
        notice($('#mvn-hardening-result'), 'خطای ارتباط', false);
      });
  });

  /* ---------- Quarantine ---------- */
  function quarantineSelectedIds() {
    return $('#mvn-quarantine-table tbody .mvn-q-check:checked')
      .map(function () {
        return $(this).val();
      })
      .get();
  }

  function quarantineUpdateBulkUi() {
    var n = quarantineSelectedIds().length;
    $('#mvn-q-restore-selected, #mvn-q-purge-selected').prop('disabled', n === 0);
    $('#mvn-q-selected-count').text(n > 0 ? n + ' مورد انتخاب شده' : '');
    var total = $('#mvn-quarantine-table tbody .mvn-q-check').length;
    var checked = $('#mvn-quarantine-table tbody .mvn-q-check:checked').length;
    $('#mvn-q-select-all').prop('checked', total > 0 && checked === total);
  }

  $(document).on('change', '#mvn-q-select-all', function () {
    var on = $(this).is(':checked');
    $('#mvn-quarantine-table tbody .mvn-q-check').prop('checked', on);
    quarantineUpdateBulkUi();
  });

  $(document).on('change', '.mvn-q-check', function () {
    quarantineUpdateBulkUi();
  });

  function runQuarantineBatch(action, ids, totalHint) {
    if (!ids.length) return;
    $('#mvn-q-progress').show();
    $('#mvn-q-restore-selected, #mvn-q-purge-selected, #mvn-q-select-all').prop('disabled', true);

    post('mvn_quarantine_batch', {
      batch_action: action,
      ids: ids,
    })
      .done(function (res) {
        if (!res || !res.success) {
          $('#mvn-q-label').text((res && res.data && res.data.message) || MVN.i18n.error);
          quarantineUpdateBulkUi();
          return;
        }
        var r = res.data;
        var remaining = r.remaining_ids || [];
        var remCount = r.remaining !== undefined ? r.remaining : remaining.length;
        var doneTotal = totalHint ? totalHint - remCount : r.done;
        var p = totalHint ? pct(doneTotal, totalHint) : 50;
        $('#mvn-q-bar').css('width', p + '%');
        var label =
          (action === 'restore' ? 'بازیابی' : 'حذف') +
          ' — انجام‌شده: ' +
          r.done +
          ' | ناموفق: ' +
          r.failed +
          ' | باقی‌مانده: ' +
          remCount;
        if (r.errors && r.errors.length) {
          label += ' — ' + r.errors.join(' | ');
        }
        $('#mvn-q-label').text(label);

        if (action === 'purge' && r.done > 0) {
          $('#mvn-quarantine-table tbody tr').each(function () {
            var qid = $(this).data('qid');
            if (qid && ids.indexOf(qid) !== -1 && remaining.indexOf(qid) === -1) {
              $(this).remove();
            }
          });
        }

        if (remCount > 0 && (r.done > 0 || r.failed === 0)) {
          setTimeout(function () {
            runQuarantineBatch(action, remaining, totalHint || ids.length);
          }, 100);
        } else {
          $('#mvn-q-label').text(MVN.i18n.done + ' — صفحه در حال تازه‌سازی...');
          setTimeout(function () {
            window.location.reload();
          }, 800);
        }
      })
      .fail(function () {
        $('#mvn-q-label').text('خطای ارتباط');
        quarantineUpdateBulkUi();
      });
  }

  $('#mvn-q-restore-selected').on('click', function () {
    var ids = quarantineSelectedIds();
    if (!ids.length) return;
    if (!window.confirm('تعداد ' + ids.length + ' فایل به مسیر اصلی برگردانده شود؟')) return;
    runQuarantineBatch('restore', ids, ids.length);
  });

  $('#mvn-q-purge-selected').on('click', function () {
    var ids = quarantineSelectedIds();
    if (!ids.length) return;
    if (!window.confirm('تعداد ' + ids.length + ' آیتم برای همیشه از قرنطینه حذف شود؟')) return;
    runQuarantineBatch('purge', ids, ids.length);
  });

  $(document).on('click', '.mvn-q-restore', function () {
    if (!window.confirm('این فایل به مسیر اصلی برگردد؟')) return;
    var id = $(this).data('id');
    var $row = $(this).closest('tr');
    post('mvn_quarantine_restore', { id: id }).done(function (res) {
      if (res && res.success) {
        alert(res.data.message);
      } else {
        alert((res && res.data && res.data.message) || MVN.i18n.error);
      }
    });
  });

  $(document).on('click', '.mvn-q-purge', function () {
    if (!window.confirm('این آیتم برای همیشه از قرنطینه حذف شود؟')) return;
    var id = $(this).data('id');
    var $row = $(this).closest('tr');
    post('mvn_quarantine_purge', { id: id }).done(function (res) {
      if (res && res.success) {
        $row.fadeOut(200, function () {
          $(this).remove();
        });
      } else {
        alert((res && res.data && res.data.message) || MVN.i18n.error);
      }
    });
  });

  /* ---- Perf / speed ---- */
  function perfNotice(msg, ok) {
    notice($('#mvn-perf-notice'), msg, ok !== false);
  }

  $('#mvn-perf-arm').on('click', function () {
    var $btn = $(this).prop('disabled', true);
    post('mvn_perf_arm', {}).done(function (res) {
      if (res && res.success) {
        perfNotice(res.data.message, true);
        setTimeout(function () {
          window.location.reload();
        }, 600);
      } else {
        $btn.prop('disabled', false);
        perfNotice((res && res.data && res.data.message) || MVN.i18n.error, false);
      }
    }).fail(function () {
      $btn.prop('disabled', false);
      perfNotice('خطای ارتباط', false);
    });
  });

  $('#mvn-perf-disarm').on('click', function () {
    var $btn = $(this).prop('disabled', true);
    post('mvn_perf_disarm', {}).done(function (res) {
      if (res && res.success) {
        perfNotice(res.data.message, true);
        setTimeout(function () {
          window.location.reload();
        }, 400);
      } else {
        $btn.prop('disabled', false);
        perfNotice((res && res.data && res.data.message) || MVN.i18n.error, false);
      }
    }).fail(function () {
      $btn.prop('disabled', false);
      perfNotice('خطای ارتباط', false);
    });
  });

  $('#mvn-perf-refresh').on('click', function () {
    window.location.reload();
  });

  $('#mvn-perf-clear').on('click', function () {
    if (!window.confirm(MVN.i18n.confirm)) return;
    var $btn = $(this).prop('disabled', true);
    post('mvn_perf_clear', {}).done(function (res) {
      if (res && res.success) {
        window.location.reload();
      } else {
        $btn.prop('disabled', false);
        perfNotice((res && res.data && res.data.message) || MVN.i18n.error, false);
      }
    }).fail(function () {
      $btn.prop('disabled', false);
      perfNotice('خطای ارتباط', false);
    });
  });

  $('#mvn-perf-optimize').on('click', function () {
    if (
      !window.confirm(
        'بهینه‌سازی خودکار اجرا شود؟\n\n• پاکسازی transient\n• حذف باقی‌مانده پلاگین‌های حذف‌شده از autoload (Xtra/Codevz، RevSlider، WOOF و …)\n• مسدودسازی دامنه مشکوک\n• حذف revision قدیمی\n• OPTIMIZE TABLE'
      )
    ) {
      return;
    }
    var $btn = $(this).prop('disabled', true);
    perfNotice('در حال بهینه‌سازی...', true);
    post('mvn_perf_optimize', {})
      .done(function (res) {
        $btn.prop('disabled', false);
        if (!(res && res.success)) {
          perfNotice((res && res.data && res.data.message) || MVN.i18n.error, false);
          return;
        }
        var d = res.data || {};
        var lines = [];
        if (d.actions && d.actions.length) {
          d.actions.forEach(function (a) {
            lines.push((a.label || a.id) + (a.count ? ' (' + a.count + ')' : ''));
          });
        }
        perfNotice((d.message || 'انجام شد') + (lines.length ? ' — ' + lines.join(' · ') : ''), true);
      })
      .fail(function () {
        $btn.prop('disabled', false);
        perfNotice('خطای ارتباط', false);
      });
  });
})(jQuery);
