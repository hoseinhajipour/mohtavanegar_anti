(function ($) {
  'use strict';

  if (typeof MVN === 'undefined') {
    return;
  }

  function post(action, data, opts) {
    data = data || {};
    data.action = action;
    data.nonce =
      MVN.nonces && MVN.nonces[action] ? MVN.nonces[action] : MVN.nonce;
    opts = opts || {};
    return $.ajax({
      url: MVN.ajax,
      method: 'POST',
      dataType: 'json',
      data: data,
      timeout: opts.timeout || 0,
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
    if (s.stats && s.stats.as) {
      parts.push('AS: ' + s.stats.as);
    }
    if (s.stats && s.stats.core) {
      parts.push('Core: ' + s.stats.core);
    }
    if (s.stats && s.stats.repo) {
      parts.push('Repo: ' + s.stats.repo);
    }
    if (s.stats && s.stats.polyglot) {
      parts.push('Polyglot: ' + s.stats.polyglot);
    }
    if (s.stats && s.stats.dropin) {
      parts.push('Drop-in: ' + s.stats.dropin);
    }
    return parts.join(' | ');
  }

  function scanPhaseLabel(s) {
    if (s.phase === 'core') {
      var extra = s.core_version ? ' (WP ' + s.core_version + ')' : '';
      return 'checksum هسته' + extra;
    }
    if (s.phase === 'repo') {
      return 'checksum مخزن' + (s.repo_label ? ' — ' + s.repo_label : '');
    }
    if (s.phase === 'db') {
      return 'دیتابیس — ' + (s.db_phase_label || s.db_phase || '...');
    }
    if (s.phase === 'as') {
      return 'Action Scheduler';
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
    $('#mvn-scan-scope, #mvn-scan-deep, #mvn-scan-core, #mvn-scan-repo, #mvn-scan-media, #mvn-scan-db, #mvn-scan-as, #mvn-scan-incremental, #mvn-scan-full').prop('disabled', active);
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

  $('#mvn-sig-pack-update').on('click', function () {
    var $btn = $(this);
    $btn.prop('disabled', true).text('در حال به‌روزرسانی...');
    $('#mvn-sig-pack-result').empty();
    post('mvn_sig_pack_update')
      .done(function (res) {
        if (!res || !res.success) {
          notice($('#mvn-sig-pack-result'), (res && res.data && res.data.message) || MVN.i18n.error, false);
        } else {
          notice($('#mvn-sig-pack-result'), (res.data && res.data.message) || 'بسته امضا به‌روز شد.', true);
        }
        $btn.prop('disabled', false).text(
          (res && res.data && res.data.sig_pack && res.data.sig_pack.has_remote)
            ? 'دریافت به‌روزرسانی امضا'
            : 'همگام‌سازی با بسته همراه پلاگین'
        );
      })
      .fail(function () {
        notice($('#mvn-sig-pack-result'), 'خطای ارتباط', false);
        $btn.prop('disabled', false);
      });
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
      scan_as: $('#mvn-scan-as').is(':checked') ? 1 : 0,
      scan_core: $('#mvn-scan-core').is(':checked') ? 1 : 0,
      scan_repo: $('#mvn-scan-repo').is(':checked') ? 1 : 0,
      scan_media: $('#mvn-scan-media').is(':checked') ? 1 : 0,
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
  function formatActivePluginsWarning(plugins) {
    var lines = plugins.map(function (p) {
      return '• ' + (p.name || p.slug) + (p.count ? ' (' + p.count + ' مورد)' : '');
    });
    return (
      'این عملیات روی فایل‌های پلاگین‌های فعال زیر اثر می‌گذارد:\n\n' +
      lines.join('\n') +
      '\n\nآیا می‌خواهید ابتدا این پلاگین‌ها غیرفعال شوند و بعد رفع انجام شود؟\n\n' +
      'OK = غیرفعال‌سازی سپس رفع\nCancel = بدون غیرفعال کردن / انصراف'
    );
  }

  function maybeDeactivateThen(plugins, onContinue, onAbort) {
    if (!plugins || !plugins.length) {
      onContinue();
      return;
    }
    var deactivate = window.confirm(formatActivePluginsWarning(plugins));
    if (!deactivate) {
      var proceed = window.confirm(
        'بدون غیرفعال کردن پلاگین‌های فعال ادامه می‌دهید؟\n(ممکن است سایت یا همان پلاگین موقتاً خطا بدهد)'
      );
      if (!proceed) {
        if (onAbort) onAbort();
        return;
      }
      onContinue();
      return;
    }
    var files = plugins.map(function (p) {
      return p.file;
    });
    post('mvn_fix_deactivate', { plugins: JSON.stringify(files) })
      .done(function (res) {
        if (!res || !res.success) {
          alert((res && res.data && res.data.message) || 'غیرفعال‌سازی ناموفق بود.');
          if (onAbort) onAbort();
          return;
        }
        onContinue();
      })
      .fail(function () {
        alert('خطای ارتباط هنگام غیرفعال‌سازی پلاگین');
        if (onAbort) onAbort();
      });
  }

  $(document).on('click', '.mvn-fix-one', function () {
    var $btn = $(this);
    var id = $btn.data('id');
    var $row = $btn.closest('tr');
    $btn.prop('disabled', true).text('...');

    function doFixOne() {
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
    }

    post('mvn_fix_preview', { id: id, filter: '' })
      .done(function (res) {
        var plugins = (res && res.success && res.data && res.data.plugins) || [];
        maybeDeactivateThen(plugins, doFixOne, function () {
          $btn.prop('disabled', false).text('رفع');
        });
      })
      .fail(function () {
        // If preview fails, still allow fix with a generic confirm.
        if (!window.confirm(MVN.i18n.confirm)) {
          $btn.prop('disabled', false).text('رفع');
          return;
        }
        doFixOne();
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
    var $btn = $(this);
    var filter = $btn.data('filter');
    if (typeof filter === 'undefined' || filter === null) {
      filter = 'safe';
    }
    var total = filter
      ? parseInt(($btn.text().match(/\((\d+)\)/) || [])[1] || '0', 10)
      : parseInt(
          ($('#mvn-fix-safe').text().match(/\((\d+)\)/) || [])[1] ||
            $('#mvn-issues-table tbody tr').length,
          10
        );
    if (!total) {
      total = $('#mvn-issues-table tbody tr').length;
    }

    if (filter === 'all' || filter === 'clean' || filter === 'quarantine') {
      var riskyOk = window.confirm(
        'این عملیات پرخطر است و ممکن است پلاگین/قالب را از کار بیندازد.\n\n' +
          'پیشنهاد: ابتدا «رفع امن» را اجرا کنید.\n\nادامه می‌دهید؟'
      );
      if (!riskyOk) return;
    }

    setFixBatchButtonsDisabled(true);
    post('mvn_fix_preview', { filter: filter })
      .done(function (res) {
        var plugins = (res && res.success && res.data && res.data.plugins) || [];
        maybeDeactivateThen(
          plugins,
          function () {
            if (!plugins.length) {
              var msg =
                filter === 'safe'
                  ? 'فقط موارد امن (بدون خطر از کار افتادن وردپرس) رفع شوند؟'
                  : MVN.i18n.confirm;
              if (!window.confirm(msg)) {
                setFixBatchButtonsDisabled(false);
                return;
              }
            }
            if (plugins.length && !window.confirm('ادامه رفع مشکلات؟')) {
              setFixBatchButtonsDisabled(false);
              return;
            }
            $('#mvn-fix-bar').css('width', '0%');
            runFixBatch(filter, total);
          },
          function () {
            setFixBatchButtonsDisabled(false);
          }
        );
      })
      .fail(function () {
        setFixBatchButtonsDisabled(false);
        if (!window.confirm(MVN.i18n.confirm)) return;
        $('#mvn-fix-bar').css('width', '0%');
        runFixBatch(filter, total);
      });
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

  /* ---------- Action Scheduler scan (standalone) ---------- */
  function runAsScanLoop() {
    post('mvn_as_scan_tick')
      .done(function (res) {
        if (!res || !res.success) {
          notice($('#mvn-as-scan-result'), (res && res.data && res.data.message) || MVN.i18n.error, false);
          $('#mvn-as-scan-start').prop('disabled', false);
          return;
        }
        var s = res.data;
        var p = pct(s.processed, s.total);
        $('#mvn-as-scan-bar').css('width', p + '%');
        $('#mvn-as-scan-pct').text(p + '%');
        $('#mvn-as-scan-label').text(
          'Action Scheduler — ' + s.processed + '/' + s.total + ' — یافته‌ها: ' + s.issue_count
        );
        if (s.status === 'running') {
          setTimeout(runAsScanLoop, 80);
        } else if (s.status === 'done') {
          var msg = 'اسکن Action Scheduler تمام شد. مشکلات: <b>' + s.issue_count + '</b>';
          if (s.issue_count > 0) {
            msg += ' — <a href="admin.php?page=mvn-fix">رفتن به رفع مشکلات</a>';
          } else {
            msg += ' — مورد مشکوکی یافت نشد.';
          }
          notice($('#mvn-as-scan-result'), msg, s.issue_count === 0);
          $('#mvn-as-scan-start').prop('disabled', false);
          if (s.issue_count > 0) {
            setTimeout(function () {
              window.location.href = 'admin.php?page=mvn-fix';
            }, 1200);
          }
        }
      })
      .fail(function () {
        notice($('#mvn-as-scan-result'), 'خطای ارتباط', false);
        $('#mvn-as-scan-start').prop('disabled', false);
      });
  }

  $('#mvn-as-scan-start').on('click', function () {
    var $btn = $(this);
    $btn.prop('disabled', true);
    $('#mvn-as-scan-progress').show();
    $('#mvn-as-scan-result').empty();
    $('#mvn-as-scan-bar').css('width', '0%');
    $('#mvn-as-scan-label').text('آماده‌سازی...');
    post('mvn_as_scan_start')
      .done(function (res) {
        if (!res || !res.success) {
          notice($('#mvn-as-scan-result'), (res && res.data && res.data.message) || MVN.i18n.error, false);
          $btn.prop('disabled', false);
          return;
        }
        var s = res.data;
        var p = pct(s.processed, s.total);
        $('#mvn-as-scan-bar').css('width', p + '%');
        $('#mvn-as-scan-pct').text(p + '%');
        if (s.status === 'done') {
          var msg = 'اسکن Action Scheduler تمام شد. مشکلات: <b>' + s.issue_count + '</b>';
          if (s.issue_count > 0) {
            msg += ' — <a href="admin.php?page=mvn-fix">رفتن به رفع مشکلات</a>';
          } else {
            msg += ' — مورد مشکوکی یافت نشد.';
          }
          notice($('#mvn-as-scan-result'), msg, s.issue_count === 0);
          $btn.prop('disabled', false);
          return;
        }
        setTimeout(runAsScanLoop, 50);
      })
      .fail(function () {
        notice($('#mvn-as-scan-result'), 'خطای ارتباط', false);
        $btn.prop('disabled', false);
      });
  });

  $('#mvn-as-purge-all').on('click', function () {
    var count = parseInt($('#mvn-as-count').text(), 10) || 0;
    var msg1 =
      'همه ردیف‌های actionscheduler_actions حذف شوند؟' +
      (count ? ' (حدود ' + count + ' مورد)' : '') +
      '\n\nلاگ‌ها و claimها هم پاک می‌شوند. این عمل برگشت‌پذیر نیست (فقط خلاصه نمونه در قرنطینه می‌ماند).';
    if (!window.confirm(msg1)) {
      return;
    }
    if (!window.confirm('تأیید نهایی: پاکسازی کامل Action Scheduler؟')) {
      return;
    }
    var $btn = $(this);
    var $scanBtn = $('#mvn-as-scan-start');
    $btn.prop('disabled', true);
    $scanBtn.prop('disabled', true);
    $('#mvn-as-scan-result').empty();
    post('mvn_as_purge_all')
      .done(function (res) {
        if (!res || !res.success) {
          notice($('#mvn-as-scan-result'), (res && res.data && res.data.message) || MVN.i18n.error, false);
          $btn.prop('disabled', false);
          $scanBtn.prop('disabled', false);
          return;
        }
        var d = res.data || {};
        var left = typeof d.count === 'number' ? d.count : 0;
        $('#mvn-as-count').text(left);
        $btn.prop('disabled', left <= 0);
        $scanBtn.prop('disabled', false);
        notice(
          $('#mvn-as-scan-result'),
          d.message ||
            'پاکسازی انجام شد. حذف‌شده: ' +
              (d.actions_deleted || 0) +
              ' — باقی‌مانده: ' +
              left,
          true
        );
      })
      .fail(function () {
        notice($('#mvn-as-scan-result'), 'خطای ارتباط', false);
        $btn.prop('disabled', false);
        $scanBtn.prop('disabled', false);
      });
  });

  /* ---------- Core repair ---------- */
  function formatCoreZipStatus(core) {
    if (!core || !core.exists) return 'فایل zip موجود نیست';
    if (!core.zip_ok) return 'آرشیو باز نمی‌شود';
    var label = 'آماده — ' + (core.files || 0) + ' ورودی';
    if (core.size) {
      var mb = (core.size / (1024 * 1024)).toFixed(1);
      label += ' / ' + mb + ' MB';
    }
    if (core.version) label += ' / نسخه ' + core.version;
    return label;
  }

  function applyCoreZipStatus(core) {
    if (!core) return;
    var $st = $('#mvn-core-zip-status');
    $st.text(formatCoreZipStatus(core));
    $st.toggleClass('mvn-ok', !!core.zip_ok).toggleClass('mvn-bad', !core.zip_ok);
    $('#mvn-core-start').prop('disabled', !core.zip_ok);
    if (core.downloaded_at) {
      var d = new Date(core.downloaded_at);
      var txt = isNaN(d.getTime())
        ? core.downloaded_at
        : d.toLocaleString('fa-IR');
      $('#mvn-core-zip-fetched').removeClass('mvn-muted').text(txt);
    }
  }

  $('#mvn-core-download').on('click', function () {
    if (!window.confirm('آخرین نسخه وردپرس از wordpress.org دانلود و جایگزین wordpress_core.zip می‌شود. ادامه؟')) {
      return;
    }
    var $btn = $(this);
    $btn.prop('disabled', true).text('در حال دریافت...');
    $('#mvn-core-start').prop('disabled', true);
    $('#mvn-core-download-result').empty();
    notice($('#mvn-core-download-result'), 'در حال دانلود از wordpress.org — ممکن است چند دقیقه طول بکشد…', true);
    post('mvn_core_download', {}, { timeout: 600000 })
      .done(function (res) {
        if (!res || !res.success) {
          notice($('#mvn-core-download-result'), (res && res.data && res.data.message) || MVN.i18n.error, false);
          $btn.prop('disabled', false).text('دریافت آخرین نسخه وردپرس');
          $('#mvn-core-start').prop('disabled', !$('#mvn-core-zip-status').hasClass('mvn-ok'));
          return;
        }
        notice($('#mvn-core-download-result'), (res.data && res.data.message) || 'دانلود موفق بود.', true);
        applyCoreZipStatus(res.data && res.data.core);
        $btn.prop('disabled', false).text('دریافت آخرین نسخه وردپرس');
      })
      .fail(function () {
        notice($('#mvn-core-download-result'), 'خطای ارتباط — دانلود ممکن است به‌خاطر حجم یا timeout قطع شده باشد.', false);
        $btn.prop('disabled', false).text('دریافت آخرین نسخه وردپرس');
        $('#mvn-core-start').prop('disabled', !$('#mvn-core-zip-status').hasClass('mvn-ok'));
      });
  });

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
          $('#mvn-core-start, #mvn-core-selective').prop('disabled', false);
        } else {
          notice($('#mvn-core-result'), 'خطا در تعمیر', false);
          $('#mvn-core-start, #mvn-core-selective').prop('disabled', false);
        }
      })
      .fail(function () {
        notice($('#mvn-core-result'), 'خطای ارتباط', false);
        $('#mvn-core-start, #mvn-core-selective').prop('disabled', false);
      });
  }

  function startCoreRepair(action, confirmMsg) {
    if (!window.confirm(confirmMsg)) return;
    $('#mvn-core-start, #mvn-core-selective').prop('disabled', true);
    $('#mvn-core-progress').show();
    $('#mvn-core-result').empty();
    post(action)
      .done(function (res) {
        if (!res || !res.success) {
          notice($('#mvn-core-result'), (res && res.data && res.data.message) || MVN.i18n.error, false);
          $('#mvn-core-start, #mvn-core-selective').prop('disabled', false);
          return;
        }
        setTimeout(runCoreLoop, 50);
      })
      .fail(function () {
        notice($('#mvn-core-result'), 'خطای ارتباط', false);
        $('#mvn-core-start, #mvn-core-selective').prop('disabled', false);
      });
  }

  $('#mvn-core-start').on('click', function () {
    startCoreRepair('mvn_core_start', 'فایل‌های هسته وردپرس از zip جایگزین می‌شوند. ادامه؟');
  });

  $('#mvn-core-selective').on('click', function () {
    startCoreRepair(
      'mvn_core_selective',
      'فقط فایل‌های تغییر یافته/گم‌شدهٔ آخرین اسکن از zip تعمیر می‌شوند. ادامه؟'
    );
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

  /* ---------- Theme repair (WordPress.org) ---------- */
  function runThemeLoop() {
    post('mvn_theme_tick')
      .done(function (res) {
        if (!res || !res.success) {
          notice($('#mvn-theme-result'), (res && res.data && res.data.message) || MVN.i18n.error, false);
          $('.mvn-theme-repair').prop('disabled', false);
          return;
        }
        var s = res.data;
        var p = pct(s.cursor, s.total);
        $('#mvn-theme-bar').css('width', p + '%');
        $('#mvn-theme-pct').text(p + '%');
        $('#mvn-theme-label').text(
          (s.name || s.slug) + ' — نوشته‌شده: ' + s.written + ' | ' + s.cursor + '/' + s.total
        );
        if (s.status === 'running') {
          setTimeout(runThemeLoop, 80);
        } else if (s.status === 'done') {
          var msg = 'تعمیر قالب «' + (s.name || s.slug) + '» تمام شد. نوشته‌شده: ' + s.written;
          if (s.skipped) msg += ' | ردشده: ' + s.skipped;
          if (s.errors && s.errors.length) {
            msg += ' — خطاها: ' + s.errors.join(' | ');
            notice($('#mvn-theme-result'), msg, false);
          } else {
            notice($('#mvn-theme-result'), msg, true);
          }
          $('.mvn-theme-repair').prop('disabled', false);
          setTimeout(function () { window.location.reload(); }, 1200);
        } else {
          notice($('#mvn-theme-result'), 'خطا در تعمیر قالب', false);
          $('.mvn-theme-repair').prop('disabled', false);
        }
      })
      .fail(function () {
        notice($('#mvn-theme-result'), 'خطای ارتباط', false);
        $('.mvn-theme-repair').prop('disabled', false);
      });
  }

  $(document).on('click', '.mvn-theme-repair', function () {
    var slug = $(this).data('slug');
    var name = $(this).data('name') || slug;
    if (!window.confirm('قالب «' + name + '» از wordpress.org جایگزین شود؟')) return;
    $('.mvn-theme-repair').prop('disabled', true);
    $('#mvn-theme-progress').show();
    $('#mvn-theme-result').empty();
    $('#mvn-theme-bar').css('width', '0%');
    $('#mvn-theme-label').text('در حال دانلود قالب از wordpress.org...');
    post('mvn_theme_start', { slug: slug })
      .done(function (res) {
        if (!res || !res.success) {
          notice($('#mvn-theme-result'), (res && res.data && res.data.message) || MVN.i18n.error, false);
          $('.mvn-theme-repair').prop('disabled', false);
          return;
        }
        setTimeout(runThemeLoop, 50);
      })
      .fail(function () {
        notice($('#mvn-theme-result'), 'خطای ارتباط (دانلود ممکن است طول بکشد)', false);
        $('.mvn-theme-repair').prop('disabled', false);
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

  $('#mvn-uploads-harden').on('click', function () {
    if (!window.confirm('deny-PHP روی پوشه uploads اعمال شود؟')) return;
    var $btn = $(this);
    $btn.prop('disabled', true);
    post('mvn_uploads_harden')
      .done(function (res) {
        if (res && res.success) {
          notice($('#mvn-uploads-harden-result'), res.data.message, true);
          if (res.data.status) {
            var st = res.data.status;
            var $el = $('#mvn-uploads-ht-status');
            if (st.hardened) {
              $el.text('محافظت فعال (deny PHP)').removeClass('mvn-bad').addClass('mvn-ok');
            } else if (!st.exists) {
              $el.text('htaccess ندارد').removeClass('mvn-ok').addClass('mvn-bad');
            } else {
              $el.text('وجود دارد ولی محافظت کامل نیست').removeClass('mvn-ok').addClass('mvn-bad');
            }
          }
        } else {
          notice($('#mvn-uploads-harden-result'), (res && res.data && res.data.message) || MVN.i18n.error, false);
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

  $('#mvn-ghost-purge').on('click', function () {
    if (
      !window.confirm(
        'پوشه/فایل‌های بدافزار + .user.ini + PHPهای hex + db.php مخرب حذف شوند؟ (چند پاس + shutdown)'
      )
    ) {
      return;
    }
    var $btn = $(this);
    $btn.prop('disabled', true);
    post('mvn_ghost_purge')
      .done(function (res) {
        if (res && res.success) {
          var ok = !(res.data.result && res.data.result.errors && res.data.result.errors.length);
          notice(
            $('#mvn-ghost-purge-result'),
            (res.data.message || '') + ' — در حال تأیید پس از رفرش…',
            ok
          );
          window.setTimeout(function () {
            window.location.reload();
          }, 2800);
        } else {
          notice($('#mvn-ghost-purge-result'), (res && res.data && res.data.message) || MVN.i18n.error, false);
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
    var payload = { settings: {}, cloak: {} };
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
      'disable_comments',
      'disable_wp_cron',
      'block_external_http',
      'block_privileged_signup',
      'login_max_attempts',
      'login_lockout_minutes',
    ];
    keys.forEach(function (k) {
      payload.settings[k] = 0;
    });
    var cloakKeys = [
      'enabled',
      'hide_wp_admin',
      'remove_meta_files',
      'block_fingerprint_files',
      'disable_emoji',
      'strip_meta_generator',
    ];
    cloakKeys.forEach(function (k) {
      payload.cloak[k] = 0;
    });
    payload.cloak.login_slug = 'mvn-access';
    payload.cloak.admin_slug = '';
    data.forEach(function (item) {
      var m = item.name.match(/^settings\[(.+)\]$/);
      if (m) {
        payload.settings[m[1]] = item.value;
      }
      var cm = item.name.match(/^cloak\[(.+)\]$/);
      if (cm) {
        payload.cloak[cm[1]] = item.value;
      }
      if (item.name === 'schedule_enabled') {
        payload.schedule_enabled = item.value;
      }
      if (item.name === 'path_blocker_enabled') {
        payload.path_blocker_enabled = item.value;
      }
    });
    post('mvn_hardening_save', payload)
      .done(function (res) {
        if (res && res.success) {
          notice($('#mvn-hardening-result'), res.data.message, true);
          if (res.data.http_guard) {
            renderHttpGuard(res.data.http_guard);
          }
          if (res.data.cloak && res.data.cloak.enabled) {
            window.setTimeout(function () {
              window.location.reload();
            }, 900);
          }
        } else {
          notice($('#mvn-hardening-result'), (res && res.data && res.data.message) || MVN.i18n.error, false);
        }
      })
      .fail(function () {
        notice($('#mvn-hardening-result'), 'خطای ارتباط', false);
      });
  });

  /* ---------- Outbound HTTP guard ---------- */
  function httpNotice(msg, ok) {
    notice($('#mvn-http-result'), msg, ok !== false);
  }

  function renderHttpGuard(data) {
    if (!data) {
      return;
    }
    var entries = data.entries || [];
    var $tbody = $('#mvn-http-tbody');
    var $table = $('#mvn-http-table');
    var $empty = $('#mvn-http-empty');
    $tbody.empty();

    $('#mvn-http-meta').text(
      entries.length +
        ' دامنه ثبت‌شده · ' +
        (data.blocked_hosts || []).length +
        ' مسدود · ' +
        (data.allowed_hosts || []).length +
        ' مجاز (استثنا)'
    );

    if (!entries.length) {
      $table.hide();
      $empty.show();
      return;
    }
    $empty.hide();
    $table.show();

    entries.forEach(function (row) {
      var host = row.host || '';
      var status = row.status || 'allowed';
      var badge;
      var action;
      if (status === 'blocked') {
        badge = '<span class="mvn-badge mvn-badge-critical">مسدود</span>';
        action =
          '<button type="button" class="button button-small mvn-http-unblock" data-host="' +
          escAttr(host) +
          '">آنبلاک</button>';
      } else if (status === 'local') {
        badge = '<span class="mvn-badge mvn-badge-info">محلی</span>';
        action = '<span class="mvn-muted">—</span>';
      } else {
        badge = '<span class="mvn-badge mvn-badge-info">مجاز</span>';
        action =
          '<button type="button" class="button button-small button-link-delete mvn-http-block" data-host="' +
          escAttr(host) +
          '">بلاک</button>';
      }
      var tr =
        '<tr data-host="' +
        escAttr(host) +
        '">' +
        '<td dir="ltr"><code>' +
        escHtml(host) +
        '</code></td>' +
        '<td>' +
        badge +
        '</td>' +
        '<td>' +
        (row.count || 0) +
        '</td>' +
        '<td>' +
        escHtml(row.last_seen_human || '') +
        '</td>' +
        '<td class="mvn-path" dir="ltr"><code>' +
        escHtml(row.last_url || '') +
        '</code></td>' +
        '<td class="mvn-actions-cell">' +
        action +
        '</td>' +
        '</tr>';
      $tbody.append(tr);
    });
  }

  function escHtml(s) {
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function escAttr(s) {
    return escHtml(s).replace(/'/g, '&#39;');
  }

  function httpAction(action, extra) {
    var payload = extra || {};
    return post(action, payload).done(function (res) {
      if (res && res.success) {
        httpNotice(res.data.message, true);
        if (res.data.http_guard) {
          renderHttpGuard(res.data.http_guard);
        }
      } else {
        httpNotice((res && res.data && res.data.message) || MVN.i18n.error, false);
      }
    }).fail(function () {
      httpNotice('خطای ارتباط', false);
    });
  }

  $('#mvn-http-refresh').on('click', function () {
    httpAction('mvn_http_guard_list');
  });

  $('#mvn-http-clear').on('click', function () {
    if (!window.confirm('لاگ درخواست‌های خروجی پاک شود؟ (فهرست بلاک/آنبلاک نگه داشته می‌شود)')) {
      return;
    }
    httpAction('mvn_http_guard_clear');
  });

  $('#mvn-http-add').on('click', function () {
    var host = $.trim($('#mvn-http-add-host').val() || '');
    if (!host) {
      httpNotice('دامنه را وارد کنید.', false);
      return;
    }
    httpAction('mvn_http_guard_add', { host: host, block: 0 }).done(function (res) {
      if (res && res.success) {
        $('#mvn-http-add-host').val('');
      }
    });
  });

  $('#mvn-http-add-block').on('click', function () {
    var host = $.trim($('#mvn-http-add-host').val() || '');
    if (!host) {
      httpNotice('دامنه را وارد کنید.', false);
      return;
    }
    httpAction('mvn_http_guard_add', { host: host, block: 1 }).done(function (res) {
      if (res && res.success) {
        $('#mvn-http-add-host').val('');
      }
    });
  });

  $(document).on('click', '.mvn-http-block', function (e) {
    e.preventDefault();
    var host = $(this).attr('data-host') || $(this).data('host');
    if (!host) {
      httpNotice('دامنه نامعتبر است.', false);
      return;
    }
    httpAction('mvn_http_guard_block', { host: String(host) });
  });

  $(document).on('click', '.mvn-http-unblock', function (e) {
    e.preventDefault();
    var host = $(this).attr('data-host') || $(this).data('host');
    if (!host) {
      httpNotice('دامنه نامعتبر است.', false);
      return;
    }
    httpAction('mvn_http_guard_unblock', { host: String(host) });
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
        'بهینه‌سازی خودکار اجرا شود؟\n\n• مسدودسازی دامنه‌های کند/خراب (مثل آپدیتور قالب که ۶ثانیه می‌ماند)\n• محدود کردن timeout HTTP خارجی\n• پاکسازی transient و Action Scheduler\n• حذف باقی‌مانده پلاگین‌های حذف‌شده از autoload\n• حذف revision قدیمی\n• OPTIMIZE TABLE + پاکسازی کش'
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

  $('.mvn-repair-rollback').on('click', function () {
    if (!window.confirm('تأیید دوم: عملیات rollback/release انجام شود؟')) return;
    var $btn = $(this).prop('disabled', true);
    var action = $btn.data('action');
    post(action, {})
      .done(function (res) {
        $btn.prop('disabled', false);
        var msg =
          (res && res.data && res.data.message) ||
          (res && res.success ? 'انجام شد.' : 'عملیات ناموفق بود.');
        notice($('#mvn-rollback-result'), msg, !!(res && res.success));
        if (res && res.success) setTimeout(function () { location.reload(); }, 1200);
      })
      .fail(function () {
        $btn.prop('disabled', false);
        notice($('#mvn-rollback-result'), 'خطای ارتباط', false);
      });
  });

  /* ---- Persistence dry-run / remediate ---- */
  $(document).on('click', '.mvn-dry-run', function () {
    var id = $(this).data('id');
    var $out = $('#mvn-dry-run-out').show().text('در حال Dry Run...');
    post('mvn_remediation_preview', { id: id }).done(function (res) {
      if (res && res.success && res.data && res.data.lines) {
        $out.text(res.data.lines.join('\n'));
      } else {
        $out.text((res && res.data && res.data.message) || MVN.i18n.error);
      }
    });
  });

  $(document).on('click', '.mvn-remediate', function () {
    var id = $(this).data('id');
    if (!window.confirm('پس از Dry Run: ابتدا Persistence سپس بدافزار قرنطینه شود؟')) return;
    var $btn = $(this).prop('disabled', true);
    post('mvn_remediation_apply', { id: id }).done(function (res) {
      $btn.prop('disabled', false);
      if (res && res.success) {
        alert('رفع انجام شد. مسیر تحت نظر Reinfection Monitor قرار گرفت.');
        location.reload();
      } else {
        alert((res && res.data && res.data.message) || MVN.i18n.error);
      }
    });
  });

  $('#mvn-persistence-selftest').on('click', function () {
    var $btn = $(this).prop('disabled', true);
    post('mvn_persistence_selftest', {}).done(function (res) {
      $btn.prop('disabled', false);
      if (res && res.success && res.data) {
        var lines = (res.data.results || []).map(function (r) {
          return (r.ok ? 'PASS' : 'FAIL') + ' #' + r.id + ' ' + r.name + ' — ' + (r.detail || '');
        });
        alert((res.data.ok ? 'Self-test OK\n' : 'Self-test FAILED\n') + lines.join('\n'));
      } else {
        alert((res && res.data && res.data.message) || MVN.i18n.error);
      }
    });
  });

  /* ---------- Security Architecture ---------- */
  var secBusy = false;
  var secRetries = 0;

  function renderPreflight(pre) {
    var $box = $('#mvn-sec-preflight-box');
    if (!$box.length || !pre || !pre.checks) return;
    var rows = pre.checks
      .map(function (c) {
        var badge = c.ok
          ? '<span class="mvn-badge mvn-badge-info">OK</span>'
          : '<span class="mvn-badge mvn-badge-critical">FAIL</span>';
        return (
          '<tr><td>' +
          $('<div>').text(c.label || '').html() +
          '</td><td>' +
          badge +
          '</td><td class="mvn-path" dir="ltr"><code>' +
          $('<div>').text(c.detail || '').html() +
          '</code></td></tr>'
        );
      })
      .join('');
    $box.html(
      '<h3>نتیجه پیش‌نیاز</h3><table class="widefat striped mvn-table"><thead><tr><th>بررسی</th><th>وضعیت</th><th>جزئیات</th></tr></thead><tbody>' +
        rows +
        '</tbody></table>'
    );
  }

  function secSetControls(running) {
    $('#mvn-sec-migrate, #mvn-sec-preflight, #mvn-sec-abort').prop('disabled', !!running);
  }

  function secTickLoop() {
    if (!secBusy) return;
    post('mvn_security_migrate_tick', {}, { timeout: 120000 })
      .done(function (res) {
        secRetries = 0;
        if (!res || !res.success) {
          secBusy = false;
          secSetControls(false);
          notice(
            $('#mvn-sec-result'),
            (res && res.data && res.data.message) || MVN.i18n.error,
            false
          );
          return;
        }
        var d = res.data || {};
        var prog = d.progress || {};
        var pctVal = 5;
        if (prog.status === 'listing') {
          pctVal = Math.min(25, 5 + Math.round((prog.offset || 0) / 500));
        } else if (prog.total) {
          pctVal = Math.min(95, Math.round((prog.offset / prog.total) * 70) + 25);
        }
        if (prog.status === 'verifying' || prog.status === 'switching') pctVal = 88;
        if (prog.status === 'testing') pctVal = 94;
        if (prog.status === 'cleanup' || d.done) pctVal = 100;
        $('#mvn-sec-progress-wrap').show();
        $('#mvn-sec-progress-bar').css('width', pctVal + '%');
        $('#mvn-sec-progress-label').text(d.message || prog.status || '…');
        if (d.payload && d.payload.log_lines) {
          $('#mvn-sec-log').show().text(d.payload.log_lines.join('\n'));
        }
        if (d.done) {
          secBusy = false;
          secSetControls(false);
          notice($('#mvn-sec-result'), d.message || 'تمام شد', true);
          window.setTimeout(function () {
            location.reload();
          }, 1200);
          return;
        }
        window.setTimeout(secTickLoop, 250);
      })
      .fail(function (xhr) {
        // Transient proxy/PHP timeouts are common on large copies — retry a few times.
        if (secRetries < 5) {
          secRetries++;
          $('#mvn-sec-progress-label').text(
            'قطع موقت ارتباط — تلاش مجدد ' + secRetries + '/5 …'
          );
          window.setTimeout(secTickLoop, 1500 * secRetries);
          return;
        }
        secBusy = false;
        secSetControls(false);
        var msg = 'خطای ارتباط — روی «ادامه مهاجرت» بزنید تا از همان‌جا ادامه شود';
        if (xhr && xhr.responseJSON && xhr.responseJSON.data && xhr.responseJSON.data.message) {
          msg = xhr.responseJSON.data.message;
        }
        notice($('#mvn-sec-result'), msg, false);
      });
  }

  $('#mvn-sec-preflight').on('click', function () {
    var $btn = $(this).prop('disabled', true);
    notice($('#mvn-sec-result'), 'در حال بررسی پیش‌نیاز…', true);
    post('mvn_security_preflight', {}, { timeout: 120000 })
      .done(function (res) {
        $btn.prop('disabled', false);
        if (res && res.success && res.data) {
          renderPreflight(res.data.preflight);
          notice($('#mvn-sec-result'), res.data.message || '', !!res.data.preflight.ok);
        } else {
          notice(
            $('#mvn-sec-result'),
            (res && res.data && res.data.message) || MVN.i18n.error,
            false
          );
        }
      })
      .fail(function () {
        $btn.prop('disabled', false);
        notice($('#mvn-sec-result'), 'خطای ارتباط', false);
      });
  });

  $('#mvn-sec-migrate').on('click', function () {
    var isResume = $(this).text().indexOf('ادامه') !== -1;
    if (!isResume) {
      var msg = $(this).data('confirm') || MVN.i18n.confirm;
      if (!window.confirm(msg)) return;
    }
    if (secBusy) return;
    secBusy = true;
    secRetries = 0;
    secSetControls(true);
    $('#mvn-sec-progress-wrap').show();
    $('#mvn-sec-progress-bar').css('width', '2%');
    $('#mvn-sec-progress-label').text(isResume ? 'ادامه مهاجرت…' : 'شروع مهاجرت…');
    post('mvn_security_migrate_start', { confirm: 'migrate' }, { timeout: 120000 })
      .done(function (res) {
        if (!res || !res.success) {
          secBusy = false;
          secSetControls(false);
          if (res && res.data && res.data.preflight) {
            renderPreflight(res.data.preflight);
          }
          notice(
            $('#mvn-sec-result'),
            (res && res.data && res.data.message) || MVN.i18n.error,
            false
          );
          return;
        }
        notice($('#mvn-sec-result'), res.data.message || 'شروع شد', true);
        secTickLoop();
      })
      .fail(function () {
        secBusy = false;
        secSetControls(false);
        notice($('#mvn-sec-result'), 'خطای ارتباط', false);
      });
  });

  $('#mvn-sec-abort').on('click', function () {
    var msg = $(this).data('confirm') || MVN.i18n.confirm;
    if (!window.confirm(msg)) return;
    var $btn = $(this).prop('disabled', true);
    post('mvn_security_migrate_abort', { confirm: 'abort' }, { timeout: 180000 })
      .done(function (res) {
        $btn.prop('disabled', false);
        if (res && res.success) {
          notice($('#mvn-sec-result'), res.data.message || 'لغو شد', true);
          window.setTimeout(function () {
            location.reload();
          }, 800);
        } else {
          notice(
            $('#mvn-sec-result'),
            (res && res.data && res.data.message) || MVN.i18n.error,
            false
          );
        }
      })
      .fail(function () {
        $btn.prop('disabled', false);
        notice($('#mvn-sec-result'), 'خطای ارتباط', false);
      });
  });

  $('#mvn-sec-rollback').on('click', function () {
    var msg = $(this).data('confirm') || MVN.i18n.confirm;
    if (!window.confirm(msg)) return;
    var $btn = $(this).prop('disabled', true);
    post('mvn_security_rollback', { confirm: 'rollback' }, { timeout: 300000 })
      .done(function (res) {
        $btn.prop('disabled', false);
        if (res && res.success) {
          notice($('#mvn-sec-result'), res.data.message || 'بازگشت انجام شد', true);
          window.setTimeout(function () {
            location.reload();
          }, 1000);
        } else {
          notice(
            $('#mvn-sec-result'),
            (res && res.data && res.data.message) || MVN.i18n.error,
            false
          );
        }
      })
      .fail(function () {
        $btn.prop('disabled', false);
        notice($('#mvn-sec-result'), 'خطای ارتباط', false);
      });
  });

  $('#mvn-sec-reverify').on('click', function () {
    var $btn = $(this).prop('disabled', true);
    post('mvn_security_reverify', {}, { timeout: 120000 })
      .done(function (res) {
        $btn.prop('disabled', false);
        if (res && res.success) {
          notice($('#mvn-sec-result'), 'تأیید سلامت انجام شد', true);
          window.setTimeout(function () {
            location.reload();
          }, 800);
        } else {
          notice(
            $('#mvn-sec-result'),
            (res && res.data && res.data.message) || MVN.i18n.error,
            false
          );
        }
      })
      .fail(function () {
        $btn.prop('disabled', false);
        notice($('#mvn-sec-result'), 'خطای ارتباط', false);
      });
  });
})(jQuery);
