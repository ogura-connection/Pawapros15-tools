# Style modules: old name -> new name

Stage 2 renamed and merged the 91 files `ui_styles_<run letter>_run<N>.py` of `pp15/art/styles/` (named after the art run and agent that wrote them) into 32 modules named after the screen or mode they style, plus `common.py` (shared drawing helpers). Style code moved verbatim; `tests/test_registry.py` proves that all 25,575 style names still select the same style (same byte code, constants and closure values), and that no name is defined in two modules.

A *style* is a recipe that tells the lettering tool how to draw an English label on a sprite sheet (font, size, colours, outline, shadow); the files in `specs/` choose one per label. See docs/GLOSSARY.md.

| old module (`ui_styles_...`) | new module (`pp15/art/styles/...`) | sprite files and screens covered | styles | spec files using it | notes |
|---|---|---|---|---|---|
| d_run2 | success_start_end.py | scs_open.arc, scs_grad.arc, scs_titl.arc, scs_intr.arc, orihen.arc; also the lazy "cut:" styles and "d:" fonts of the generators | 52 | scs_grad, scs_intr, orihen, scs_titl, sct_titl, scs_open |  |
| a_run2 | success_start_end.py | scs_end.arc: end of a Success game | 3345 | scs_end |  |
| a_run9 | success_main.py | scs_main.arc, scs_data.arc, scs_rens.arc, scs_make.arc: leftover pages | 63 | scs_main, scs_rens, scs_data, scs_make |  |
| f_run10 | success_main.py | scs_rens.arc z3_smr_0 icons, Super Ability GET!, Hot Blood | 3 | scs_rens |  |
| e_run2 | success_main.py | sn_abiup.arc, scs_load.arc, scs_make.arc, scs_rens.arc, scs_b_ed.arc | 16 | sn_abiup, scs_load, scs_b_ed, scs_rens |  |
| c_run3 | success_main.py | are_abi.arc: the player-data screen of Arrange and of Success's Linked World | 12 | are_abi |  |
| f_run2 | success_main.py | scg_camp.arc (elite squad camp mini-games), scs_g_ed.arc (draft announcements), gdt_sch.arc | 42 | scg_camp, scs_g_ed, gdt_sch |  |
| c_run2 | success_main.py | gdt_scs.arc (Success match labels), scs_vs.arc (versus screen), scs_win.arc (result screen) | 28 | gdt_scs, scs_win, scs_vs |  |
| b_run2 | success_scenarios.py | scs_sce2.arc, scs_sce3.arc: scenario 3 job list, company names, training screen | 66 | scs_sce3, scs_sce2 |  |
| b_run3 | success_scenarios.py | scc_tops.arc: the Linked World screens (bank z4_li_0) | 16 | scc_tops |  |
| vs_flame | success_versus.py | scs_vs.arc z5_svs_0: the big animated "versus" redrawn as an italic VS | 14 | scs_vs |  |
| a_run3 | logo_front_panel.py | scc_tops.arc: the Success banner and the logos of Hakkyu Dream and Eikan Nine (redrawn whole, cut into windows) | 8 | scc_tops |  |
| p_run11 | logo_pictures.py | scc_tops.arc / scs_titl.arc: the Hakkyu Dream logo (y5_tic_0 pages 0-1) | 5 |  |  |
| b_run9 | logo_pictures.py | big title logos painted into pictures that the game cuts over several pages (homerun, pena_ini, pn_acivt, ore_ini) | 40 | homerun, pena_ini, pn_acivt, ore_ini | reads the original .arc through pp15/art/original_arc.py (was _work scripts) |
| l_run11 | logo_title_screens.py | scc_tops.arc panel and the scs_titl.arc / sct_titl.arc title screens: English logos of Hakkyu Dream and Eikan Nine | 12 | scc_tops, sct_titl, scs_titl |  |
| d_run4 | eikan_main.py | sct_main.arc, gdt_sct.arc, sct_a_sc.arc, sct_a_it.arc, sct_sugo.arc | 1837 | sct_main, sct_a_sc, gdt_sct, sct_a_pd, sct_a_it, sct_sugo |  |
| e_run4 | eikan_main.py | school_g.arc, sct_card.arc, sct_comd.arc, sct_a_ed.arc, sct_a_od.arc | 28 | sct_card, school_g, sct_comd, sct_a_ed, sct_a_od |  |
| zzzz_leftd | eikan_main.py | sct_sugo.arc: the big Eikan date card (second z4_emp_0 bank) | 17 | sct_sugo, order, sct_a_ar |  |
| sip_comm | eikan_main.py | sip_comm.arc bank r4_smo: the inning card of the Eikan Nine practice game | 2 | sip_comm |  |
| ek_strip | eikan_menus.py | sct_sugo.arc z4_emp_0: the Eikan Nine main screen (weekday strip, event cards of the progress-icon board) | 75 | sct_sugo, sct_a_ar |  |
| a_run4 | eikan_menus.py | sct_a_mk.arc, gdt_sch.arc, sct_a_lb.arc | 48 | sct_a_mk, gdt_sch, sct_a_lb |  |
| b_run4 | eikan_menus.py | sct_titl.arc, sct_g_cd.arc, sct_a_pr.arc, sct_a_sy.arc | 18 | sct_a_pr, sct_g_cd, sct_titl, sct_a_sy |  |
| fix_D_eikan | eikan_menus.py | Eikan Nine fix (fxD_...): sct_a_mk.arc | 1 | sct_a_mk |  |
| g_run10 | eikan_menus.py | lettering of code-drawn atlases painted in place (sct_main.arc, school_g.arc, ore_ini.arc; names g10_*) | 9 | sct_main, ore_ini, school_g |  |
| c_run4 | eikan_school.py | school.arc, sct_a_ar.arc, sct_a_nh.arc, sct_a_td.arc | 191 | sct_a_ar, school, sct_a_td, sct_a_nh | reads the original .arc through pp15/art/original_arc.py (was _work scripts) |
| a_run5 | pennant.py | pennant.arc | 162 | pennant |  |
| a_run6 | pennant.py | pn_trade.arc, gdt_pn.arc, pnbg_sum.arc, pnbg_fal.arc (trades, season summary) | 31 | pn_trade, pnbg_sum, pnbg_fal, gdt_pn | 4 definitions dropped: overridden by zz_reader2 |
| b_run6 | pennant.py | pn_gaijn.arc, gdt_npn.arc (foreign players) | 52 | gdt_npn, pn_gaijn | 3 definitions dropped: overridden by zz_reader2 |
| d_run6 | pennant.py | pn_fa.arc, pn_tgrow.arc | 26 | pn_fa, pn_tgrow | 2 definitions dropped: overridden by zz_reader2 |
| b_run5 | pennant_sub.py | pena_sub.arc: s3_opc_0, s3_pir00, s3_pih00 | 9 | pena_sub |  |
| c_run5 | pennant_sub.py | pena_sub.arc: s3_phg00, b5_pe00, s3_pen00, s3_pnd00 | 1411 | pena_sub |  |
| d_run5 | pennant_sub.py | pena_sub.arc: r5_ren, r5_renz, s3_pic00 .. g3_ps_0 | 112 | pena_sub |  |
| e_run5 | pennant_sub.py | pena_sub.arc: Pennant sub-screens | 1720 | pena_sub |  |
| fix_B_pennant | pennant_sub.py | Pennant fixes (fxB_...) | 16 | pena_sub, pena_ini, rec_room |  |
| c_run6 | pennant_start.py | pena_ini.arc, dft_meet.arc, mbg_2gun.arc, pnbg_rai.arc | 284 | pena_ini, dft_meet, mbg_2gun, pnbg_rai |  |
| e_run6 | pennant_start.py | draft.arc, pn_deban.arc, pnbg_spr.arc, pnbg_win.arc | 40 | draft, pn_deban, pnbg_spr, pnbg_win | 4 definitions dropped: overridden by zz_reader2 |
| c_run7 | arrange.py | arrange.arc, teammark.arc | 235 | arrange, teammark | 3 definitions dropped: overridden by zz_reader2 |
| d_run7 | arrange.py | are_sub.arc: m3_are, s4w_are, m3_oen, m3_ido, m3_inst, m3_pss, m3_seiseki, s4_mem00 | 7230 | are_sub |  |
| b_run7 | arrange.py | arr_org.arc: original-team creation | 32 | arr_org | 1 definitions dropped: overridden by zz_reader2 |
| a_run7 | arrange_sub.py | arr_sub.arc | 210 | arr_sub |  |
| e_run7 | arrange_edit.py | chrsong.arc, arr_chg.arc, arr_num.arc | 293 | chrsong, arr_chg, arr_num | 14 definitions dropped: overridden by zz_reader2 |
| f_run7 | arrange_edit.py | arr_sub.arc: s3_kh, s3_kkw, s3_ks, s3_kss, s3_t, s4r_sh00, z3_ait_0 | 27 | arr_sub | 4 definitions dropped: overridden by zz_reader2 |
| f_run7b | arrange_edit.py | arr_sub.arc: plates | 6 | arr_sub |  |
| f_run7c | arrange_edit.py | arr_sub.arc: windows of the s3_kkw lettering | 18 | arr_sub | reads STYLES["f7_kkw"] instead of typeset.RENDER["f7_kkw"] |
| ore_ini | my_life_screens.py | ore_ini.arc: title buttons, team choice, profile screens | 10 | ore_ini | helper _orig_page moved to common.py; helper ringfill moved to common.py |
| ore_ini_card | my_life_screens.py | ore_ini.arc: the profile card lists (banks y3_mym, y3_mys) | 9 | ore_ini |  |
| orepena | my_life_screens.py | orepena.arc: HUD, settings, file select, tabs | 64 | orepena |  |
| mylife | my_life_screens.py | My Life tabs | 1 | orepena |  |
| fix_A_mylife_orepena | my_life_screens.py | orepena.arc fixes (fxA_...) | 12 | orepena |  |
| ore_ren | my_life_practice.py | ore_ren.arc: practice menu (banks g3_0ren .. g3_3ren) | 15 | ore_ren |  |
| ore_sub | my_life_practice.py | ore_sub.arc: schedule screen (bank y3_yotei) | 30 | ore_sub |  |
| ore_sub2 | my_life_practice.py | ore_sub.arc: r5_ut (vessel), r5_tsu (bonds), y3_prof (profile) | 14 | ore_sub |  |
| ore_sub3 | my_life_practice.py | ore_sub.arc: y3_kine (trophy room), y3_pmoji (profile words) | 6 | ore_sub |  |
| ore_fa | my_life_practice.py | ore_fa.arc: free agency (bank y3_fa) | 6 | ore_fa |  |
| ore_i_co | my_life_practice.py | ore_i_co.arc: the button hints (bank y4_btn) | 8 | ore_i_co |  |
| orepena2 | my_life_report.py | orepena.arc: banks w5_kek, w5_kek00, y3_k, y3_pnews, y3_mjun (results report, game tags, pro news) | 41 | orepena |  |
| myend | my_life_report.py | myend.arc: My Life ending (banks y3_end, y3_se16, y3_se256) | 31 | myend |  |
| orepena3 | my_life_chapters.py | orepena.arc: b5_m00, b5_mm, g3_rire, y3_file, y3_hist, y3_jim0, y3_jim1, y3_m256 and the chapter cards | 30 | orepena |  |
| ore_myk | my_life_chapters.py | ore_myk.arc: records screens (bank y3_my) | 8 | ore_myk |  |
| ore_ini_card2 | my_life_chapters.py | ore_ini.arc: prefectures and background of the card (y3_myk), wife and children (y3_kzo) | 6 | ore_ini |  |
| gdt_ore | my_life_match.py | gdt_ore.arc: My Life match overlays (h3_apm_0, y3_ss, y4_ind_0) | 15 | gdt_ore |  |
| gdt_ore_cd | my_life_match.py | gdt_ore.arc: My Life stat tickers (bank y3_cd) | 1 | gdt_ore |  |
| match | match.py | time.arc, gameplay.arc, main_prg.arc: umpire's calls, pause menu, pitch chart, player panel, substitution screen | 15 | time, gameplay, main_prg |  |
| match_intro | match.py | dscn_str.arc, gameplay.arc: the team / stadium name atlas of the match intro | 3 | gameplay, dscn_str |  |
| match_ps2 | match.py | gameplay.arc bank h3_ap_ps2: score bug, batter / pitcher panels, swing tags | 5 | gameplay |  |
| match_ulk | match.py | main_prg.arc bank h3_ulk_0: inning, home-run number, distance, replay banners | 7 | main_prg |  |
| d_run1 | match.py | gameplay.arc: defensive shift panel, record banners, team names, position tags | 191 | gameplay |  |
| f_run1 | match.py | order.arc, vs_st.arc | 19 | order, vs_st |  |
| e_run1 | match.py | scorebook tags, team initials, plates, shift editor (main_prg.arc, shift_ed.arc) | 23 | main_prg, shift_ed |  |
| a_run8 | records_room.py | rec_room.arc: pages of g3_gkn, g3_mvp, g3_nen | 13 | rec_room | 2 definitions dropped: overridden by zz_reader2 |
| b_run8 | records_room.py | rec_room.arc: pages of g2_ck, g3_ft, g3_syo, g3_npk | 37 | rec_room |  |
| c_run8 | records_room_extra.py | rec_room.arc: part 3 | 38 | rec_room | 7 definitions dropped: overridden by zz_reader2 |
| d_run8 | game_results.py | record.arc: g3_kn, g3_ke, g3_kekx | 111 | record | 14 definitions dropped: overridden by zz_reader2 |
| e_run8 | camp_remopawa.py | camp.arc, homerun.arc, calorie.arc, gdt_remo.arc, gdt_camp.arc (camp styles generated by gen_camp_spec.py) | 684 | camp, homerun, calorie, gdt_remo, gdt_camp | 102 definitions dropped: overridden by zz_reader2, zzz_camp |
| zzz_camp | camp_remopawa.py | camp.arc | 60 | camp | 60 definitions replace those of e_run8 |
| fix_C | camp_remopawa.py | Success fixes (fxC_...): camp.arc | 2 | camp |  |
| e_run10 | champion.py | chmp_c.arc, chmp_m.arc, gdt_cham.arc | 89 | chmp_c, chmp_m, gdt_cham |  |
| c_run9 | champion.py | homerun.arc, chmp_e.arc, chmp_t.arc, champion.arc | 131 | homerun, chmp_e, chmp_t, champion |  |
| q_run11 | champion.py | gdt_cham.arc, chmp_c.arc, gdt_hr.arc, gameplay.arc, order.arc | 102 | gdt_cham, chmp_c, gdt_hr, gameplay, order |  |
| h_run10 | champion.py | homerun.arc: the r3_hr heading | 1 | homerun |  |
| f_run8 | contract_talks.py | koukai.arc, chmp_t.arc, chmp_m.arc, champion.arc, chmp_e.arc, remopawa.arc | 534 | koukai, chmp_t, chmp_m, champion, chmp_e, remopawa | 19 definitions dropped: overridden by zz_reader2 |
| c_run1 | main_menu.py | vs.arc, sd_mode.arc, title.arc, dem_open.arc | 1086 | dem_open, vs, sd_mode, title | helper win moved to common.py |
| a_run1 | controller.py | ctrler.arc: controller settings and control guide screens | 86 | ctrler |  |
| b_run1 | settings.py | option.arc: the match options screen (bank g3_ops) | 3871 | option |  |
| voice | settings.py | arevoice.arc: the voice settings screen (bank m3_onsei) | 32 | arevoice | helper flat moved to common.py |
| cheer_menu | settings.py | chrsong.arc: the Cheer Song menu (r3_okf) | 6 | chrsong |  |
| d_run9 | settings.py | arekore.arc, main_prg.arc, m_logo.arc and other leftovers (names d9_*) | 18 | arekore, main_prg, m_logo, orepena, rec_room |  |
| fix_E_other | late_fixes.py | fixes of several screens (fxE_...): champion.arc, order.arc, chmp_t.arc, arr_sub.arc, arrange.arc | 41 | champion, order, arrange, arr_sub, chmp_t, gameplay |  |
| fix_left | late_fixes.py | leftover fixes (fxL_): orepena.arc, scs_main.arc, rec_room.arc, sct_a_od.arc | 5 | rec_room, scs_main, sct_a_od, orepena |  |
| fix_A_mylife | late_fixes.py | My Life fixes (fxA_...) | 4 | koukai, ore_ren |  |
| zz_reader2 | late_fixes.py | overrides | 119 | homerun, record, chmp_t, rec_room, chrsong, arr_num | 119 definitions replace those of a_run6, a_run8, b_run6, b_run7, c_run7, c_run8, d_run6, d_run8, e_run6, e_run7, e_run8, f_run7, f_run8 |

## New modules

| module | what it styles |
|---|---|
| common.py | Drawing helpers shared by the other style modules (it defines no styles itself). |
| success_start_end.py | Styles for the opening and ending screens of Success Mode (the story mode in which you build a player). |
| success_main.py | Styles for the main screens of Success Mode, the story mode in which you build a player. |
| success_scenarios.py | Styles for the scenario screens of Success Mode and for its Linked World screens. |
| success_versus.py | Style for the big "VS" that flashes between the two teams before a Success Mode match. |
| logo_front_panel.py | Styles for the big logos on the front panel of Success Mode: the Success banner and the logos of the two games Hakkyu Dream and Eikan Nine. |
| logo_pictures.py | Styles for large English title logos that are pictures cut over several pages of a sprite sheet. |
| logo_title_screens.py | Styles for the English logos of Hakkyu Dream and Eikan Nine on the Success Mode front panel and title screens. |
| eikan_main.py | Styles for the main screens of Eikan Nine, the Success Mode scenario in which you manage a high-school baseball team. |
| eikan_menus.py | Styles for the menus of Eikan Nine, the Success Mode scenario in which you manage a high-school team. |
| eikan_school.py | Styles for the Baseball School and the team-management lists of Eikan Nine. |
| pennant.py | Styles for Pennant mode (managing a pro team through a season): the main screen, trades, season summary, foreign players, free agency and training growth. |
| pennant_sub.py | Styles for the many sub-screens of Pennant mode (the biggest Pennant file): rosters, reports, results and settings. |
| pennant_start.py | Styles for starting a Pennant season and for the draft: team set-up, the draft meeting, the draft board and the season-start backgrounds. |
| arrange.py | Styles for Arrange mode (editing teams and players): the team arrangement screens, team marks, the member lists and original-team creation. |
| arrange_sub.py | Styles for the sub-screens of Arrange mode (the arr_sub sprite file). |
| arrange_edit.py | Styles for the change and number screens of Arrange mode, the Cheer Song menu pages, and the lettering, plates and windows of the arr_sub sprite file. |
| my_life_screens.py | Styles for My Life mode (living a pro player's career): the title buttons, team choice, profile screens and card lists, and the in-game HUD, settings, file select and tabs. |
| my_life_practice.py | Styles for the My Life practice menu, schedule screen, free agency screen and button hints. |
| my_life_report.py | Styles for the My Life results report, game tags and pro news, and for the career ending screen. |
| my_life_chapters.py | Styles for the My Life chapter cards, file and history pages, records screens, and the prefecture and family pages of the profile card. |
| my_life_match.py | Styles for the overlays and stat tickers that My Life shows during a match. |
| match.py | Styles for the match screens: the umpire's calls, pause menu, pitch chart, player panels, scoreboard, substitution, lineup and batting-order screens, and the team and stadium names of the match intro. |
| records_room.py | Styles for the Records Room: pages of season and career records (games played, home runs, average and so on). |
| records_room_extra.py | Styles for more pages of the Records Room (season and career records). |
| game_results.py | Styles for the Game Results screens (the list of past games and their scores). |
| camp_remopawa.py | Styles for the practice camp, the Home Run Derby mini-game, the motion-controller (Remo-Pawa) screens and the calorie test. |
| champion.py | Styles for Champion mode (a tournament): bracket and game screens, rock-paper-scissors, rules, and home-run records. |
| contract_talks.py | Styles for the contract negotiation screen (offers, talks, money in yen), plus some Champion mode and Remo-Pawa labels. |
| main_menu.py | Styles for the main menu and system screens: the versus menu, sound mode selection, the title screen, and the playoff and stage cards. |
| controller.py | Styles for the controller settings and control guide screens. |
| settings.py | Styles for settings screens: match options, voice settings, the Cheer Song menu and the Data Corner (password entry and display, jersey names, stats settings). |
| late_fixes.py | Styles added late to fix individual labels that looked wrong on several different screens. |

## Duplicate style names

179 names were defined in two modules; the later module in file-name order won (it replaced the earlier one in `typeset.RENDER`), and every one of the two definitions differed. Each name now has only the winning definition, kept in the module of the screen it belongs to (the winner's text replaced the loser's line).

| winner (old module) | overridden (old module) | names |
|---|---|---|
| zzz_camp | e_run8 | 60 |
| zz_reader2 | e_run8 | 42 |
| zz_reader2 | f_run8 | 19 |
| zz_reader2 | d_run8 | 14 |
| zz_reader2 | e_run7 | 14 |
| zz_reader2 | c_run8 | 7 |
| zz_reader2 | a_run6 | 4 |
| zz_reader2 | e_run6 | 4 |
| zz_reader2 | f_run7 | 4 |
| zz_reader2 | b_run6 | 3 |
| zz_reader2 | c_run7 | 3 |
| zz_reader2 | a_run8 | 2 |
| zz_reader2 | d_run6 | 2 |
| zz_reader2 | b_run7 | 1 |

The winners all come from two modules: `zz_reader2` (ringfill styles read again from the Japanese lettering) and `zzz_camp` (camp styles read again). Those modules now hold nothing of their own; `zz_reader2` is gone and its lines sit where the overridden ones were. One name (`c8_018`) stays in `late_fixes.py` because its winner uses the shared `flat` helper and the module of the overridden definition (`records_room_extra.py`) has a different `flat`.
