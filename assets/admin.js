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

  /* ---------- Scan ---------- */
  function runScanLoop() {
    post('mvn_scan_tick')
      .done(function (res) {
        if (!res || !res.success) {
          notice($('#mvn-scan-result'), (res && res.data && res.data.message) || MVN.i18n.error, false);
          return;
        }
        var s = res.data;
        var p = pct(s.processed, s.total);
        $('#mvn-scan-bar').css('width', p + '%');
        $('#mvn-scan-pct').text(p + '%');
        $('#mvn-scan-label').text(
          'بررسی‌شده: ' + s.processed + ' / ' + s.total + ' — یافته‌ها: ' + s.issue_count
        );
        var st = s.stats || {};
        $('#mvn-scan-stats').text(
          'بحرانی: ' +
            (st.critical || 0) +
            ' | هشدار: ' +
            (st.warning || 0) +
            ' | htaccess: ' +
            (st.htaccess || 0) +
            ' | PHP: ' +
            (st.php || 0)
        );

        if (s.status === 'running') {
          setTimeout(runScanLoop, 80);
        } else if (s.status === 'done') {
          $('#mvn-scan-label').text(MVN.i18n.done);
          var html =
            '<div class="mvn-notice mvn-notice-ok">اسکن تمام شد. تعداد مشکلات: <b>' +
            s.issue_count +
            '</b>. ';
          if (s.issue_count > 0) {
            html +=
              '<a href="admin.php?page=mvn-fix">رفتن به صفحه رفع مشکلات</a>';
          }
          html += '</div>';
          $('#mvn-scan-result').show().html(html);
          $('#mvn-scan-start').prop('disabled', false);
        } else {
          notice($('#mvn-scan-result').show(), 'وضعیت نامشخص: ' + s.status, false);
          $('#mvn-scan-start').prop('disabled', false);
        }
      })
      .fail(function () {
        notice($('#mvn-scan-result').show(), 'خطای ارتباط با سرور', false);
        $('#mvn-scan-start').prop('disabled', false);
      });
  }

  $('#mvn-scan-start').on('click', function () {
    var $btn = $(this);
    $btn.prop('disabled', true);
    $('#mvn-scan-progress').show();
    $('#mvn-scan-result').hide().empty();
    $('#mvn-scan-bar').css('width', '0%');
    $('#mvn-scan-label').text(MVN.i18n.scanning);

    post('mvn_scan_start', {
      scope: $('#mvn-scan-scope').val(),
      deep: $('#mvn-scan-deep').is(':checked') ? 1 : 0,
    })
      .done(function (res) {
        if (!res || !res.success) {
          notice($('#mvn-scan-result').show(), (res && res.data && res.data.message) || MVN.i18n.error, false);
          $btn.prop('disabled', false);
          return;
        }
        setTimeout(runScanLoop, 50);
      })
      .fail(function () {
        notice($('#mvn-scan-result').show(), 'خطای ارتباط با سرور', false);
        $btn.prop('disabled', false);
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
  function runFixBatch(filter, totalHint) {
    $('#mvn-fix-progress').show();
    post('mvn_fix_batch', { filter: filter || '' })
      .done(function (res) {
        if (!res || !res.success) {
          $('#mvn-fix-label').text((res && res.data && res.data.message) || MVN.i18n.error);
          return;
        }
        var r = res.data;
        var rem = r.remaining || 0;
        var doneHint = totalHint ? totalHint - rem : r.fixed;
        var p = totalHint ? pct(doneHint, totalHint) : 50;
        $('#mvn-fix-bar').css('width', p + '%');
        $('#mvn-fix-label').text(
          'رفع‌شده در این دسته: ' + r.fixed + ' | ناموفق: ' + r.failed + ' | باقی‌مانده: ' + rem
        );
        if (rem > 0 && (r.fixed > 0 || r.failed === 0)) {
          setTimeout(function () {
            runFixBatch(filter, totalHint || rem + r.fixed);
          }, 100);
        } else {
          $('#mvn-fix-label').text(MVN.i18n.done + ' — صفحه را تازه کنید.');
          setTimeout(function () {
            window.location.reload();
          }, 800);
        }
      })
      .fail(function () {
        $('#mvn-fix-label').text('خطای ارتباط');
      });
  }

  $('#mvn-fix-all, #mvn-fix-htaccess, #mvn-fix-clean, #mvn-fix-uploads').on('click', function () {
    if (!window.confirm(MVN.i18n.confirm)) return;
    var filter = $(this).data('filter') || '';
    var total = $('#mvn-issues-table tbody tr').length;
    $(this).prop('disabled', true);
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
})(jQuery);
