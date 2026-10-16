"""Style reader v2 overrides (tools/restyle.py): ringfill styles read again from the Japanese.
Loaded after the agents' files (name sorts last), so these definitions win. Votes and an example sprite in each comment."""
from ui_styles_ore_ini import ringfill
from ui_styles_voice import flat

STYLES = {}

STYLES["a6_empty"] = ringfill([8, 8, 8, 8, 8, 8], [11, 11, 11, 11])    # 1/1 votes, e.g. pn_trade g3_pt_0 66
STYLES["a6_pt_title"] = ringfill([1, 1, 1, 1, 1, 1], [5, 5, 5])    # 4/4 votes, e.g. pn_trade g3_pt_0 3f
STYLES["a6_ptk_big"] = ringfill([1, 1, 1, 1, 1, 1], [10, 10, 10, 10])    # 1/1 votes, e.g. pn_trade g3_ptk_0 20
STYLES["a6_pts_head"] = flat([0, 1, 1, 1, 1, 1, 1], cut=3)    # 3/6 votes, e.g. pn_trade g3_pts_0 09
STYLES["a8_gkn"] = ringfill([15, 15, 15, 15, 15, 15], [1, 1])    # 68/99 votes, e.g. rec_room g3_gkn#12+g3_ji#13 00
STYLES["a8_gkn_71"] = ringfill([8, 8, 8, 8, 8, 8], [1, 1], [15])    # 1/1 votes, e.g. rec_room g3_gkn#12+g3_ji#13 71
STYLES["b6_g3_pg_0_129"] = ringfill([11, 11, 11, 11, 11, 11], [5, 2], [5, 13])    # 1/2 votes, e.g. pn_gaijn g3_pg_0 0d
STYLES["b6_g3_pg_0_134"] = ringfill([1, 1, 1, 1, 1, 1], [9, 10, 10])    # 1/1 votes, e.g. pn_gaijn g3_pg_0 28
STYLES["b6_g3_pg_0_153"] = flat([0, 1, 1, 1, 1, 1, 1], cut=3)    # 1/1 votes, e.g. pn_gaijn g3_pg_0 29
STYLES["b7_okp_tab"] = ringfill([14, 14, 14, 14, 14, 14], [6])    # 9/10 votes, e.g. arr_org s3_okp 0c
STYLES["c7_am_2a_y"] = ringfill([15, 15, 15, 15, 15, 15], [5])    # 1/1 votes, e.g. arrange s3_am 2a
STYLES["c7_am_names"] = ringfill([15, 15, 15, 15, 15, 15], [2])    # 13/14 votes, e.g. arrange s3_am 41
STYLES["c7_s3_am_1e"] = ringfill([15, 15, 15, 15, 15, 15], [9, 9])    # 1/1 votes, e.g. arrange s3_am 1e
STYLES["c8_005"] = ringfill([12, 12, 12, 12, 12, 12], [1])    # 1/1 votes, e.g. rec_room g2_km#2+g3_sm#3 49
STYLES["c8_008"] = ringfill([15, 15, 15, 15, 15, 15], [3, 6])    # 1/1 votes, e.g. rec_room g3_gk#17+g3_ndn#18 00
STYLES["c8_018"] = flat([0, 1, 1, 1, 1, 1, 1], cut=3)    # 1/1 votes, e.g. rec_room g3_gol#8+g3_syo#9 06
STYLES["c8_023"] = ringfill([12, 12, 12, 12, 12, 12], [1, 15])    # 1/1 votes, e.g. rec_room g3_ndn#18+g3_tbk#19 00
STYLES["c8_029"] = ringfill([1, 1, 1, 1, 1, 1], [11, 11])    # 2/3 votes, e.g. rec_room g3_tbk#19+g3_npk#20 00
STYLES["c8_031"] = ringfill([1, 1, 1, 1, 1, 1], [8])    # 2/2 votes, e.g. rec_room g3_tbk#19+g3_npk#20 04
STYLES["c8_041"] = ringfill([15, 15, 15, 15, 15, 15], [7, 7], [7])    # 32/42 votes, e.g. rec_room g3_sm#3+g3_top#4 04
STYLES["d6_cyan"] = ringfill([8, 8, 8, 8, 8, 8], [10, 1])    # 1/1 votes, e.g. pn_fa g3_fa_0 9d
STYLES["d6_title"] = ringfill([2, 2, 2, 2, 2, 2], [9, 11, 11])    # 2/3 votes, e.g. pn_fa g3_fa_0 01
STYLES["d8_g3_ke_03"] = ringfill([15, 15, 15, 15, 15, 15], [8])    # 1/1 votes, e.g. record g3_ke 03
STYLES["d8_g3_ke_06"] = ringfill([15, 15, 15, 15, 15, 15], [8])    # 1/1 votes, e.g. record g3_ke 06
STYLES["d8_g3_ke_07"] = ringfill([15, 15, 15, 15, 15, 15], [8])    # 1/1 votes, e.g. record g3_ke 07
STYLES["d8_g3_ke_0a"] = ringfill([15, 15, 15, 15, 15, 15], [8])    # 1/1 votes, e.g. record g3_ke 0a
STYLES["d8_g3_ke_0d"] = ringfill([15, 15, 15, 15, 15, 15], [8])    # 1/1 votes, e.g. record g3_ke 0d
STYLES["d8_g3_ke_0e"] = ringfill([15, 15, 15, 15, 15, 15], [8])    # 1/1 votes, e.g. record g3_ke 0e
STYLES["d8_g3_ke_a5"] = ringfill([15, 15, 15, 15, 15, 15], [8])    # 1/1 votes, e.g. record g3_ke a5
STYLES["d8_g3_kn_0a"] = ringfill([15, 15, 15, 15, 15, 15], [7, 7])    # 1/1 votes, e.g. record g3_kn 0a
STYLES["d8_g3_kn_0d"] = ringfill([15, 15, 15, 15, 15, 15], [7, 7])    # 1/1 votes, e.g. record g3_kn 0d
STYLES["d8_g3_kn_0f"] = ringfill([15, 15, 15, 15, 15, 15], [7, 7])    # 1/1 votes, e.g. record g3_kn 0f
STYLES["d8_g3_kn_10"] = ringfill([15, 15, 15, 15, 15, 15], [7, 7])    # 1/1 votes, e.g. record g3_kn 10
STYLES["d8_g3_kn_13"] = ringfill([15, 15, 15, 15, 15, 15], [7, 7])    # 1/1 votes, e.g. record g3_kn 13
STYLES["d8_g3_kn_34"] = ringfill([15, 15, 15, 15, 15, 15], [8])    # 1/1 votes, e.g. record g3_kn 34
STYLES["d8_g3_kn_35"] = ringfill([15, 15, 15, 15, 15, 15], [8])    # 1/1 votes, e.g. record g3_kn 35
STYLES["e6_b5"] = ringfill([2, 2, 2, 2, 2, 2], [14])    # 6/10 votes, e.g. pn_deban b5_r00 00
STYLES["e6_ks_pick"] = ringfill([15, 15, 15, 15, 15, 15], [4])    # 2/2 votes, e.g. pn_deban m3_ksd_0 20
STYLES["e6_pd_red"] = flat([0, 1, 1, 1, 1, 1, 1], cut=3)    # 1/1 votes, e.g. draft g3_pd_0 48
STYLES["e6_pd_title"] = ringfill([14, 14, 14, 14, 14, 14], [1, 6, 6, 6])    # 2/2 votes, e.g. draft g3_pd_0 12
STYLES["e7_r4_chm_04_3_h"] = ringfill([15, 15, 15, 15, 15, 15], [12, 9])    # 1/1 votes, e.g. chrsong r4_chm 04
STYLES["e7_r4_chm_7b_h"] = ringfill([7, 7, 7, 7, 7, 7], [3])    # 1/1 votes, e.g. chrsong r4_chm 7b
STYLES["e7_r4_chm_7f_h"] = ringfill([6, 6, 6, 6, 6, 6], [4], [1, 1])    # 1/1 votes, e.g. chrsong r4_chm 7f
STYLES["e7_r4_chm_80_h"] = ringfill([6, 6, 6, 6, 6, 6], [4], [1, 1])    # 1/1 votes, e.g. chrsong r4_chm 80
STYLES["e7_r4_chm_b1_h"] = ringfill([15, 15, 15, 15, 15, 15], [6, 6])    # 1/1 votes, e.g. chrsong r4_chm b1
STYLES["e7_r4_chm_b6_h_s"] = ringfill([15, 15, 15, 15, 15, 15], [7])    # 1/1 votes, e.g. chrsong r4_chm b6
STYLES["e7_r4_chm_d4_h"] = ringfill([7, 7, 7, 7, 7, 7], [1, 1])    # 1/1 votes, e.g. chrsong r4_chm d4
STYLES["e7_r4_chm_d5_h"] = ringfill([7, 7, 7, 7, 7, 7], [1, 1])    # 1/1 votes, e.g. chrsong r4_chm d5
STYLES["e7_s3_no_24_h"] = flat([0, 1, 1, 1, 1, 1, 1], cut=3)    # 1/1 votes, e.g. arr_num s3_no 24
STYLES["e7_s3_no_25_h"] = flat([0, 1, 1, 1, 1, 1, 1], cut=3)    # 1/1 votes, e.g. arr_num s3_no 25
STYLES["e7_s3_no_26_h"] = flat([0, 1, 1, 1, 1, 1, 1], cut=3)    # 1/1 votes, e.g. arr_num s3_no 26
STYLES["e7_s3_no_27_h"] = flat([0, 1, 1, 1, 1, 1, 1], cut=3)    # 1/1 votes, e.g. arr_num s3_no 27
STYLES["e7_s3_no_28_h"] = flat([0, 1, 1, 1, 1, 1, 1], cut=3)    # 1/1 votes, e.g. arr_num s3_no 28
STYLES["e7_s3_no_2d_h"] = flat([0, 1, 1, 1, 1, 1, 1], cut=3)    # 1/1 votes, e.g. arr_num s3_no 2d
STYLES["e8_r3_hr_3b_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [15])    # 1/1 votes, e.g. homerun r3_hr 3b
STYLES["e8_r3_hr_3c_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [15])    # 1/1 votes, e.g. homerun r3_hr 3c
STYLES["e8_r3_hr_3d_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [15])    # 1/1 votes, e.g. homerun r3_hr 3d
STYLES["e8_r3_hr_3e_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [15])    # 1/1 votes, e.g. homerun r3_hr 3e
STYLES["e8_r3_hr_3f_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [15])    # 1/1 votes, e.g. homerun r3_hr 3f
STYLES["e8_r3_hr_40_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [15])    # 1/1 votes, e.g. homerun r3_hr 40
STYLES["e8_r3_hr_41_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [15])    # 1/1 votes, e.g. homerun r3_hr 41
STYLES["e8_r3_hr_42_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [15])    # 1/1 votes, e.g. homerun r3_hr 42
STYLES["e8_r3_hr_43_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [15])    # 1/1 votes, e.g. homerun r3_hr 43
STYLES["e8_r3_hr_44_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [15])    # 1/1 votes, e.g. homerun r3_hr 44
STYLES["e8_r3_hr_45_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [15])    # 1/1 votes, e.g. homerun r3_hr 45
STYLES["e8_r3_hr_46_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [15])    # 1/1 votes, e.g. homerun r3_hr 46
STYLES["e8_r3_hr_47_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [15])    # 1/1 votes, e.g. homerun r3_hr 47
STYLES["e8_r3_hr_48_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [15])    # 1/1 votes, e.g. homerun r3_hr 48
STYLES["e8_r3_hr_49_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [15])    # 1/1 votes, e.g. homerun r3_hr 49
STYLES["e8_r3_hr_4a_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [15])    # 1/1 votes, e.g. homerun r3_hr 4a
STYLES["e8_r3_hr_4b_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [15])    # 1/1 votes, e.g. homerun r3_hr 4b
STYLES["e8_r3_hr_4c_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [15])    # 1/1 votes, e.g. homerun r3_hr 4c
STYLES["e8_r3_hr_4d_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [15])    # 1/1 votes, e.g. homerun r3_hr 4d
STYLES["e8_r3_hr_4e_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [15])    # 1/1 votes, e.g. homerun r3_hr 4e
STYLES["e8_r3_hr_4f_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [15])    # 1/1 votes, e.g. homerun r3_hr 4f
STYLES["e8_r3_hr_50_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [15])    # 1/1 votes, e.g. homerun r3_hr 50
STYLES["e8_r3_hr_51_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [15])    # 1/1 votes, e.g. homerun r3_hr 51
STYLES["e8_r3_hr_52_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [15])    # 1/1 votes, e.g. homerun r3_hr 52
STYLES["e8_r3_hr_53_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [15])    # 1/1 votes, e.g. homerun r3_hr 53
STYLES["e8_r3_hr_54_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [15])    # 1/1 votes, e.g. homerun r3_hr 54
STYLES["e8_r3_hr_55_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [15])    # 1/1 votes, e.g. homerun r3_hr 55
STYLES["e8_r3_hr_56_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [15])    # 1/1 votes, e.g. homerun r3_hr 56
STYLES["e8_r3_hr_57_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [15])    # 1/1 votes, e.g. homerun r3_hr 57
STYLES["e8_r3_hr_58_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [15])    # 1/1 votes, e.g. homerun r3_hr 58
STYLES["e8_r3_hr_59_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [15])    # 1/1 votes, e.g. homerun r3_hr 59
STYLES["e8_r3_hr_5a_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [15])    # 1/1 votes, e.g. homerun r3_hr 5a
STYLES["e8_r3_hr_5b_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [15])    # 1/1 votes, e.g. homerun r3_hr 5b
STYLES["e8_r3_hr_5c_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [15])    # 1/1 votes, e.g. homerun r3_hr 5c
STYLES["e8_r3_hr_79_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [15])    # 1/1 votes, e.g. homerun r3_hr 79
STYLES["e8_r3_hr_7a_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [15])    # 1/1 votes, e.g. homerun r3_hr 7a
STYLES["e8_r3_hr_92_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [15])    # 1/1 votes, e.g. homerun r3_hr 92
STYLES["e8_r3_hr_93_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [15])    # 1/1 votes, e.g. homerun r3_hr 93
STYLES["e8_r3_hr_94_h_s"] = ringfill([1, 1, 1, 1, 1, 1], [15])    # 1/1 votes, e.g. homerun r3_hr 94
STYLES["e8_y4_miiset_00_h"] = ringfill([15, 15, 15, 15, 15, 15], [5], [4, 4])    # 1/1 votes, e.g. gdt_remo y4_miiset 00
STYLES["e8_y4_miiset_01_h"] = ringfill([15, 15, 15, 15, 15, 15], [10, 5])    # 1/1 votes, e.g. gdt_remo y4_miiset 01
STYLES["e8_y4_miiset_02_h"] = ringfill([15, 15, 15, 15, 15, 15], [5], [4, 4])    # 1/1 votes, e.g. gdt_remo y4_miiset 02
STYLES["f7_kh_cancel2"] = ringfill([15, 15, 15, 15, 15, 15], [9, 9, 4])    # 1/1 votes, e.g. arr_sub s3_kh 02
STYLES["f7_kh_help"] = flat([0, 1, 1, 1, 1, 1, 1], cut=3)    # 25/26 votes, e.g. arr_sub s3_kh 3e
STYLES["f7_sh_relief"] = ringfill([15, 15, 15, 15, 15, 15], [8])    # 1/1 votes, e.g. arr_sub s4r_sh00 1e
STYLES["f7_t_col"] = ringfill([1, 1, 1, 1, 1, 1], [15, 15])    # 4/9 votes, e.g. arr_sub s3_t 12
STYLES["f8_r3_chpab_14"] = ringfill([15, 15, 15, 15, 15, 15], [7])    # 1/1 votes, e.g. champion r3_chpab#3+r3_chpab#3@r3_jk 14
STYLES["f8_r3_ted_00"] = ringfill([5, 5, 5, 5, 5, 5], [11])    # 1/1 votes, e.g. chmp_e r3_ted 00
STYLES["f8_r3_ted_01"] = ringfill([5, 5, 5, 5, 5, 5], [10])    # 1/1 votes, e.g. chmp_e r3_ted 01
STYLES["f8_r3_ted_0b"] = ringfill([15, 15, 15, 15, 15, 15], [1])    # 1/1 votes, e.g. chmp_e r3_ted 0b
STYLES["f8_r3_ted_19"] = ringfill([4, 4, 4, 4, 4, 4], [11])    # 1/1 votes, e.g. chmp_e r3_ted 19
STYLES["f8_r3_ted_1f_s"] = ringfill([15, 15, 15, 15, 15, 15], [1])    # 1/1 votes, e.g. chmp_e r3_ted 1f
STYLES["f8_r3_ten_1e"] = ringfill([1, 1, 1, 1, 1, 1], [11, 11])    # 1/1 votes, e.g. chmp_t r3_ten 1e
STYLES["f8_r3_ten_35_66"] = ringfill([15, 15, 15, 15, 15, 15], [9, 9])    # 1/1 votes, e.g. chmp_t r3_ten 35
STYLES["f8_r3_ten_53_66"] = ringfill([15, 15, 15, 15, 15, 15], [9, 9])    # 1/1 votes, e.g. chmp_t r3_ten 53
STYLES["f8_r3_th_06_29"] = ringfill([15, 15, 15, 15, 15, 15], [9])    # 1/1 votes, e.g. chmp_m r3_th 06
STYLES["f8_r3_tig_0_0a"] = ringfill([1, 1, 1, 1, 1, 1], [8, 8])    # 1/1 votes, e.g. chmp_t r3_tig_0 0a
STYLES["f8_r3_tig_0_0b"] = ringfill([1, 1, 1, 1, 1, 1], [8, 8])    # 1/1 votes, e.g. chmp_t r3_tig_0 0b
STYLES["f8_r3_tig_0_0c"] = ringfill([1, 1, 1, 1, 1, 1], [8, 8])    # 1/1 votes, e.g. chmp_t r3_tig_0 0c
STYLES["f8_r3_tig_0_0d"] = ringfill([1, 1, 1, 1, 1, 1], [8, 8])    # 1/1 votes, e.g. chmp_t r3_tig_0 0d
STYLES["f8_r3_tig_0_0e"] = ringfill([1, 1, 1, 1, 1, 1], [8, 8])    # 1/1 votes, e.g. chmp_t r3_tig_0 0e
STYLES["f8_r3_tig_0_0f"] = ringfill([1, 1, 1, 1, 1, 1], [8, 8])    # 1/1 votes, e.g. chmp_t r3_tig_0 0f
STYLES["f8_r3_tvs_18"] = ringfill([1, 1, 1, 1, 1, 1], [6, 15, 6])    # 1/1 votes, e.g. chmp_m r3_tvs 18
STYLES["f8_r3_tvsx_06_0"] = ringfill([207, 207, 207, 207, 207, 207], [157, 80, 230, 157])    # 1/1 votes, e.g. chmp_m r3_tvsx 06
STYLES["f8_r3_tvsx_07_0"] = ringfill([207, 207, 207, 207, 207, 207], [157, 80, 157, 157])    # 1/1 votes, e.g. chmp_m r3_tvsx 07
