# Translation style: Jikkyou Powerful Pro Yakyuu 15, Japanese to English

Method borrowed from the `srt-pipeline` repo (`docs/ja-to-en.md`): fix the voices and the recurring
terms in a context file first, then translate scene by scene against it.

## Principle

Pawapuro is a Japanese institution. The English should read as a Japanese game in English, not as
an American baseball game. Keep the setting, the social relations and the way people talk. Do not
swap in American equivalents, and do not footnote. Faithful, but never stiff, cute or over the top.

Priorities, highest first:
1. What the character is trying to do or feel in the line.
2. The character's voice (register, tics, dialect).
3. Natural English.
4. The facts of the line.
5. Literal wording. Sentence-final particles become tone, not tag questions.

## Fixed rules

- **Names:** family name first (Yabe Akio). Hepburn without macrons (Koshien, Tokyo, senpai).
- **Spelling and idiom:** American spelling and neutral phrasing (honor, practice, the field,
  the store). No regional slang, British or American. Old-fashioned or formal wording is fine
  where it is a character's voice (Tamano, the bucho, Yabe). Plain ASCII only: the pair font
  has no accented letters.
- **Honorifics:** keep `-san`, `-kun`, `-chan`, `-senpai`, `-sensei`. They carry the relationships.
  A character who drops them is being rude or close, and that must stay visible.
- **Japanese terms that stay as they are:** Koshien, senpai, kohai, bento, and other words an
  English reader of a Japanese game knows or can pick up. Add to the glossary as they come up.
- **Setting:** yen, km/h, metres, school years, company ranks (bucho, shacho) stay Japanese.
  No dollars, mph or American league terms.
- **Baseball terms:** standard English baseball words for the game itself (strikeout, bunt,
  hit by pitch for デッドボール). Japan-specific institutions keep their identity (Koshien,
  the draft, industrial-league ball for 社会人野球).
- **Voices are locked.** Once a character has a register and a tic, they never change unless the
  story makes them. Give every main character an entry below with one example line before
  translating their scenes.
- **Recurring phrases are locked.** One English rendering each, listed under Running beats.

## Dialect and speech quirks

Everything is rendered in English. No romaji dialect words, no Japanese sentence endings glued
onto English, no invented spellings, and no English regional accent standing in for a Japanese one.

- **Kansai-ben:** the voice comes through in how the character talks, in plain English: blunt,
  quick, warm, teasing, fond of a comeback, more casual and direct than the people around them.
  The reader should hear a different temperament from a Tokyo speaker without any marked words.
- **Verbal tics (語尾):** give the character one consistent English speech habit that does the same
  job (how they end a thought, a pet phrase, how they refer to themselves). Use it sparingly:
  often enough to be recognisable, never on every line. Yabe's `でやんす` marks him as a humble,
  eager sidekick, so his English habit should say that. Pick it from sample lines and lock it.
- **First-person words:** オレ, ボク, オイラ, ワシ, 私 all say something. Show it through register
  (rough, boyish, folksy, old man, polite), not through odd pronouns.
- **Old men's `じゃ` / `のう`:** plain, slightly old-fashioned English. No "ye olde".
- **Sound effects:** translate the sense, keep them short ("(Knock knock)").

## Characters

Scenario 1 (株式会社パワフル, `scs_sce1.rel`). Agreed on 2026-10-12: these voices are locked.
Line counts are text runs in scenario 1.

### 主人公 / the player [MAIN, about 800 lines]
- Calls people: Yabe-kun, Maruo (no honorific), Todoroki-senpai, Momoko-chan, Bucho, Shacho, Kantoku.
- Contractions: YES
- Register: オレ. Earnest, boyish, quick to cheer and quick to grumble. Casual with Yabe, Maruo and
  Momoko; polite with the bucho, the shacho and Todoroki ("sir", full sentences). His thoughts and the
  narration are casual, first person, past tense.
- Habit: none. He is the straight man; keep him plain so the others stand out.
- Example: "Taxes sure are steep. Being a working adult is rough..."

### 矢部明雄 / Yabe Akio [MAIN, about 215 lines]
- Calls people: (player)-kun, Todoroki-senpai, Kagurazaka-kun.
- Contractions: YES
- Register: オイラ + でやんす. Cheerful, humble, eager sidekick with a cheeky streak and a habit of
  blunt truths said politely. A little prim: "kindly", "I must say", "I'm afraid", "who might you be".
- Habit (carries でやんす / オイラ): now and then he calls himself "yours truly", most often when
  boasting or feeling sorry for himself. Not every time he says オイラ.
- Locked: a stand-alone やんす！ is "Yes indeed!" (said alongside the others' "Yes, sir!").
- Example: "Yours truly, as of today, is the super rookie who will take this company by storm."

### 轟大助 / Todoroki Daisuke [MAIN, about 545 lines]
- Captain and ace of the company team, the player's senpai at work. Calls people by bare family name
  (the player, Yabe, Hanai). Calls Tamano "Kantoku".
- Contractions: YES
- Register: 俺 + だ / ぜ / だな. Warm, steady, hot-blooded. Short confident sentences, fond of a
  lesson and a maxim. Never slangy, never sarcastic.
- Habit: repeats the key word for emphasis when he preaches ("Heart. Heart!").
- Example: "What matters for us is heart. Heart! Never lose on spirit. Never."

### 矢島勤造 / Yajima Kinzo, the bucho [MAIN, about 235 lines]
- Calls the player by bare name, お前 when cross, キサマ when furious. Calls Momoko "Hanai-kun".
- Contractions: NO (this is what makes him sound stiff)
- Register: 私 + だ / のだ / うむ. Pompous, strict, turns every chore into a principle of working
  life. Orders, not requests. Fair underneath: he praises good work and hands out a Pawarin.
- Habit: grand statements about trivial jobs. Opens with "good timing" when he has a chore.
- Example: "A small smudge today, a great stain tomorrow. And then society itself decays."

### 玉野球太郎 / Tamano Kyutaro, shacho and kantoku [MAIN, about 270 lines]
- President of the company in the office, manager of the team on the field. Calls the player
  (name)-kun or "kimi" in the office, お前 on the field.
- Contractions: NO, or very few
- Register: ワシ + じゃ / のう / わい. Kindly old man, plain and slightly old-fashioned English
  ("I shall", "splendid", "a bitter pity"). Baseball-mad; gets emotional about his team.
- Habit: thinks aloud with "Hm, hm." before an answer (ふむふむ).
- Example: "It is nothing grand, but it should help your practice."

### 丸尾一平 / Maruo Ippei [MAIN, about 115 lines]
- A year below the player and more talented. Calls him "senpai" or (name)-san, and Tamano "Kantoku".
- Contractions: YES
- Register: ボク + ッス. Breezy junior: respectful on the surface, cheeky and money-minded
  underneath. Clipped sentences that often drop the "I" ("Joined to play ball!", "Will do!").
  Says "senpai" a lot. Laughs "Heh heh" (えへへ).
- Habit: the dropped subject and the "senpai" are the ッス.
- Example: "Heh heh. That'll be 500 yen for the massage, please."

### 花井桃子 / Hanai Momoko [MAIN, about 55 lines]
- Joined the same year as the player. Calls him (name)-kun. He calls her Momoko-chan, the bucho
  calls her Hanai-kun, Todoroki calls her Hanai.
- Contractions: YES
- Register: 私 + よ / ね / の. Bright, kind, a bit scatterbrained. Light and warm, never gushing.
  Can be cold in one line when the story needs it (the break-up).
- Example: "Baseball and work are fine, but you need a breather now and then."

### 神楽坂光彦 / Kagurazaka Mitsuhiko [RIVAL, about 25 lines]
- Heir of the Kagurazaka Group, star pitcher, "the Prince". Calls the player (name)-kun.
- Contractions: YES
- Register: ボク, with a pause before the last particle (だ、ね / だ、よ / 、さ) and a pink heart.
  Vain, amused, generous in defeat.
- Habit: a comma, then one small closing word: ね "no?", よ "you know", さ "see", ぞ "got it". The
  heart glyph stays where the Japanese has it. His showy word games (ＭＩＤＯＲＩ, ＰＵＮ・ＳＵＫＡ)
  become showy English in capitals ("MIX & MATCH", "HUFF-PUFF").
- Example: "Heh heh... Quite the celebration, no?"

### Voices set while translating the Data screen

Chosen on 2026-10-12 from each character's rating comments and their scenes; treat as locked unless the
scenario translation shows a reason to change one. Names are romanised from the readings the scenes give;
which comment group belongs to which character was worked out from speech patterns, not confirmed in game.

| Character | Japanese markers | English |
|---|---|---|
| Takeda Keiji | オレ + ねえ / ぜ | rough, loud, loyal jock; "pal", sparingly |
| Tojo Kojiro | 俺, 以上だ | cold, grave, clipped, NO contractions; closes with a flat verdict: "That is all." |
| Koshihaba Tsukuo | drawled endings, doubled words | sneering senpai; repeats the jeering word ("No good, no good!") |
| Morita | オレ + だ / ぞ, flames | booming big brother; calls everyone "Brother", talks in fire |
| Matsuo | dots and a glare | one or two words: "...Impressive." |
| Zento Kaoru | オレ様 | swaggering tough guy who measures everyone against himself; no odd pronoun |
| Tanakayama Taro | だぞ on every sentence | plain, earnest everyman; "for sure", sparingly |
| Takumi Hayato | speed talk | cocky and competitive; speed and keeping up |
| Mido Kintaro | Kansai-ben | by the Kansai rule: blunt, quick, warm, teasing, no marked words |
| Namigashira Shibuki | barked っ, fish words | hearty man of the sea, short sentences; fish images |
| Hamu Reito | ボク + ねえ / かな | silky charmer who judges by shine; trailing "I'd say" |
| 男前田 / Otokomaeda Yohei | である | stiff, no contractions |
| Otori Nagamichi | lecherous old man | "Hyo hyo hyo" |
| Otori Kanna | casual | contractions |
| 根霧 蓮 / Negiri Ren (shop clerk) | わよ / からね, うふ | warm, confident older-sister tone; "Hee hee." only where the Japanese has うふ |

### Names and voices set for the bulk translation (2026-10-13)

Readings are the ones the scripts give. These went into the translators' brief and are used throughout
`scs_main.rel`, `scs_sce2.rel` and `scs_sce3.rel`.

| Character | English | Voice |
|---|---|---|
| 神楽坂光成 | Kagurazaka Mitsunari | CEO of the Kagurazaka Group, Mitsuhiko's doting father (ワシ + なのだ): grand, no contractions |
| 男前田洋平 | Otokomaeda Yohei | Kantoku of the Kagurazaka Group team |
| 六道聖 | Rokudo Hijiri | flat, composed, old-fashioned plain speech; Hijiri-chan |
| 猪狩守 / 猪狩進 | Ikari Mamoru / Ikari Susumu | genius ace who looks down on everyone / his polite brother |
| 友沢亮 | Tomozawa Ryo | cool, proud, few words |
| 早川あおい / 橘みずき | Hayakawa Aoi / Tachibana Mizuki | earnest and fair / bossy and teasing |
| 阿畑やすし | Abata Yasushi | Kansai rule |
| ダイジョーブ博士 / ゲドー君 | Daijobu Hakase / Gedo-kun | grand, stilted, no contractions, "science" / only "Gyo." |
| 加藤京子 | Kato Kyoko | hospital nurse; smooth, teasing |
| 日和ミヨ | Hiyori Miyo | Miyo-san |
| 鳳永路 | Otori Nagamichi | runs the club team Otori Phoenix (鳳フェニックス) |
| 白健二 | Haku Kenji | |
| 猛田慶次 | Takeda Keiji | タケさん is Take-san; Morita is アニキ, "Aniki" |
| 店長 / 博士 | Tencho / Hakase | as forms of address, like Kantoku |

Scenario 2 terms: 一級 / 二級 / 三級社員 are Grade 1 / 2 / 3 employees; 昇格 / 降格 promoted / demoted.
Company and club teams: the name romanised, the business translated (ぴちぴち水産 Pichipichi Fisheries).

### Minor voices
- **親父 (the player's father):** gruff shopkeeper, やがれ. Short and rough, soft underneath.
- **母さん (mother):** warm and plain. "Take care of yourself."
- **影山 (Kageyama, the scout):** calm professional talking to himself. Todoroki is "Todoroki-kun".
- **Team mates and fans:** one-liners. Team mates casual and rough, fans squeal.
- **Narration:** the player, first person, past tense. **System messages:** neutral, "you".
- **System-screen helpers** (one set of 9 help lines per helper): neutral; Tamano (locked voice);
  a stern manager (short orders, "Careful:"); an old codger (ぞい: "eh?", "it does", "Mind,");
  a gruff manager (plain, one contraction); a girl (わよ / からね: "Let's", "okay?"); the dog
  (ワン: one "Woof!" at the start of the line, never more).
- **Tips (サクちょこ = "Success Tips"):** friendly and plain, "you", no contractions needed.
- **Glossary pop-ups (【 】):** one or two dictionary-style sentences.

## Running beats (locked renderings)

| Japanese | English |
|---|---|
| 株式会社パワフル | Pawafuru Corp. (the game's own logo reads PAWAFURU CORPORATION) |
| やんす！ (alone) | Yes indeed! |
| よし / よーし | Okay, / Okay! |
| はい！ / はいっ！ to a superior | Yes, sir! |
| やったー！ | All right! (good news) / We did it! (a win) |
| ふぅ、疲れた。 | Phew, I'm worn out. |
| そんなこんなで | And so |
| ちょうどよかった (bucho) | good timing |
| よくやったぞ！ (bucho) | Well done! |
| ふむふむ、ナルホド (Tamano) | Hm, hm. I see, I see. |
| みんな頼んだぞ (Tamano) | I'm counting on you all. |
| 無念じゃ (Tamano) | A bitter pity. |
| がんばってくれよ (Tamano) | Give it your all. |
| くっそー！負けてしまった・・・ | Damn it! We lost... |
| やったッス！ / 残念ッス・・・ (Maruo) | We did it! / What a shame... |
| えへへ / エヘヘ (Maruo) | Heh heh. |
| そして試合当日・・・ / 次の日・・・ / 数日後・・・ | And then, game day... / The next day... / A few days later... |

## Glossary

| Japanese | English | Notes |
|---|---|---|
| サクセス | Success Mode | |
| 甲子園 | Koshien | |
| 親父 / 母さん / 父さん / せがれ | old man / Mom / Dad / son | the player and his parents |
| 社会人野球 | the industrial leagues; industrial-league (adjective) | |
| 社会人 | working adult | |
| 社長 / 部長 / 課長 / 係長 | Shacho / Bucho / Kacho / Kakaricho | also as forms of address |
| 平社員 | rank and file | never used as an address |
| 監督 | Kantoku | as an address; "the manager" when described |
| キャプテン | Captain | |
| 都市対抗 | the Intercity Tournament | 予選 qualifiers, 全国大会 the nationals |
| 日本選手権 | the Japan Championship | |
| 全国制覇 | the national title | |
| 強化指定選手 / 合宿 | elite squad / elite squad camp | |
| ドラフト | the draft | |
| 神楽坂グループ | the Kagurazaka Group | |
| 黒獅子重工 | Kurojishi Heavy Industries | "Kurojishi" after the first mention |
| 覇王 | Hao | mystery team |
| 王子 / 御曹司 | the Prince / heir | Kagurazaka |
| パワリン | Pawarin | energy drink |
| パワスポニュース / パワフルスポーツ | PawaSpo News / Pawafuru Sports | |
| 決算 / 中間決算 | closing of the books / half-year results | |
| 給料日 / 大入り袋 | payday / bonus envelope | |
| 体力 / やる気 | vitality / motivation | the gauges; "Vitality" is the official English term and keeps 体力 apart from the pitcher stat スタミナ (Stamina) |
| 熱血練習 | Hot-Blooded Practice | |
| 熱血 / 熱血度 (the gauge) | Passion | the HUD gauge that fills up and sets off Hot-Blooded Practice: "Your Passion is full." |
| 熱血状態 / 熱血発動中 | fired up / Fired Up! | the state while the gauge is spent |
| もう一丁練習 | One-More Practice | from もう一丁！ "One more!" |
| 練習器材 | training gear | |
| チーム方針 | team policy | |
| ベンチ入り / スタメン | make the bench / starter | |
| 特殊能力 | special ability | |
| 広角打法 / プルヒッター | Spray Hitter / Pull Hitter | MLB Power Pros names |
| ノビ / キレ / ジャイロボール | Fastball Life / Spin / Gyroball | MLB Power Pros plate names. Spin is キレ (graded: Spin 4, Spin 2); until 2026-10-12 this row wrongly gave Spin for ジャイロボール |
| ムービングファスト / ツーシーム | Moving Fastball / 2-Seamer | |
| サボりぐせ / 弱気 | Laziness / Timidity | MLB Power Pros names |
| 世渡り上手 / いいやつ / 寝坊 | Smooth Talker / Good Guy / Oversleeper | |
| 爆弾 | time bomb | the hidden injury risk |
| ラブパワー / 街の人々 | Love Power / the Townsfolk | |
| 経験点 / 故障率 | experience points / Injury rate | |
| 白球ドリーム / 栄冠ナイン | Hakkyu Dream / Eikan Nine | the two Success games |
| リンクする世界 / 選手名鑑 | Linked World / Player Directory | |
| スカウト評価 / 監督の評価 | scout rating / Kantoku's rating | |
| 野球偉人伝 | Lives of the Baseball Greats | |
| てるてる坊主 | teru teru bozu | |
| （カキーン！） / （ズバーン！） | (Crack!) / (Thwack!) | bat / mitt |
| （ブルンッ！） / （ビュッ！） | (Whoosh!) / (Zip!) | swing / pitch |
| （カリカリ） / （ヒソヒソ） | (Scribble scribble) / (Whisper whisper) | |
| せっせ、せっせ | Busy, busy... | |
| パワプロ１５ / 決定版 | Pawapuro 15 / Pawapuro 15 Ketteiban | in system dialogs |
| 対戦 / ペナント / マイライフ / アレンジ / ホームラン競争 | Exhibition / Pennant / My Life / Arrange / Home Run Derby | game modes |
| 応援曲 / ごほうび選手 / ＯＢ選手 | cheer song / bonus player / OB player | |
| よろしいですか？ | Is this OK? | every system dialog |
| Ｗｉｉ本体保存メモリ | Wii System Memory | Nintendo's terms for all system words (SD Card, Wii Operations Manual, Data Management screen, blocks) |
| ○ / × / ◎ on an ability | Gd / Pr / Grt | MLB plate style: Gd Bunt, Pr Morale, Grt Catcher |
| 筋力 / 敏捷 / 技術 / 変化球 / 精神 ポイント | Strength / Quickness / Technique / Breaking Ball / Mentality Points | MLB names |
| 走力 / 肩力 in short slots | SPD / ARM | RUN SPD and ARM STR on the stat plates |
| 装備 | equip, equipment | never "gear": that is the training gear |
| 達人 (item names) | Pro | Pro Bat, Pro Glove |

## Eikan Nine (set for the bulk translation, 2026-10-13)

- The student manager addresses the player as "Kantoku". The boy (僕, 〜ッス) is an eager junior: short sentences, "sir" now and then. The girl (私, 〜ですね) is bright and tidy. A line without a marker is written so either could say it.
- Narration is the kantoku in the first person; result lines have no subject ("All players' grades went up.").
- Panels: White / Blue / Red / Green / Yellow Panel, Schedule Panel. 進行アイコン progress icon, 戦術アイコン tactic icon, 特訓 Special Training, 世間の評判 public reputation, 信頼度 trust, 新入部員 new recruits, 練習試合 practice game.
- School reputation ranks: 弱小 Weak, そこそこ Fair, 中堅 Mid, 強豪 Good, 名門 Top. Prefectures romanised without the suffix; 北北海道 N. Hokkaido, 東東京 E. Tokyo.
- A line holds 36 letters. The whole script must fit the bytes of the Japanese (the build checks).

## Limits set by the game

- 34 letters per line. Speech bubbles and the status-screen message box hold 3 lines; the letterbox
  narration of the opening holds 2. One more line scrolls the first away (measured in Dolphin).
- Keep the line count of the original box unless the English truly needs one more and it fits.
- One entry per text run. Where a sentence is split into several runs on one line (colour change,
  inserted name, the heart), give the earlier run an even number of letters. `tl.py merge` checks this.
- Inserted player names are still Japanese and can be 6 cells (12 letters) wide: do not write
  sentences that depend on an English name, and leave room on that line.
- The script marks the speaker (portrait), colour changes and line breaks; `tl.py export` shows them.

## Working notes (from scenario 1)

- Workflow: `tl.py show FILE A B` prints scenes, `tl.py apply FILE` stores English (one line per run,
  `-` for an empty run), `tl.py merge` checks everything, then `rebuild_scripts.py build`.
- Text the game inserts in mid-sentence (ranks, item names, team names) is itself a run somewhere
  else in the file. Give it an even number of letters, with a leading space if needed (` kacho`),
  and end the run before it without a space. Write the sentence so nothing depends on the insert's
  grammar ("Promoted to" + rank + "!").
- Where the Japanese puts a name and its reading on one line, the reading run becomes empty and
  the honorific goes into the coloured name run ("Todoroki Daisuke-senpai!").
- Menus are still Japanese on screen, so a line that tells the player where to go quotes the
  Japanese label as it is.
- The son calls his father "old man" (親父) and his mother "Mom". Team names in the standings stay as fans say them
  (Giants, Hanshin, Chunichi, SoftBank).
- Lines from `scs_main.rel` (common events, sound effects, "you met Yabe" notices) appear inside
  scenario scenes and stay Japanese until that file is translated.

## UI graphics

Only lettering is replaced. Icons, characters, logos and any picture without text stay exactly as
Konami drew them, so the game keeps its own look. English labels are taken from the official
English games where they exist in the same art style; nothing MLB- or 2K-branded is used.

Words on screen (Success Mode), with where the lettering comes from:

| Japanese | English | Lettering |
|---|---|---|
| 練習 / 通院 / お店 / データ / システム / 能力アップ | Practice / Hospital / Shop / Data / System / Boost | MLB 2008 art, as drawn |
| お出かけ | Free Time | MLB 2008 art: the series' name for this slot of the command bar |
| 休む / 仕事 / アイテム / 遊ぶ / デート / 試合 / リスト / 治療 | Rest / Work / Items / Play / Date / Game / List / Treat | set from MLB letters (G, I, J and b derived) |
| 仕事探す / 仕事する | Jobs / Work | set from MLB letters |
| stat labels | TRJ, CON, PWR, RUN SPD, ARM STR, FLD, E RES, TOP SPD, CTRL, STAM, Position | MLB 2008 art |
| 体力 / 熱血 / やる気 / 所持金 / 天気 | Vitality / Passion / Motivation / Money / Weather | tag font (drawn for this patch) |
| 熱血発動中 | Fired Up! | Arial Rounded Bold |
| 天気予報 | Forecast | Arial Rounded Bold (plate), tag font (button hint) |
| 年目 / 月 / 週 | Yr / Mo / Wk | Times New Roman Bold Italic, to go with the game's italic numerals. The game draws the number first, so the unit follows it: 1Yr 9Mo 1Wk |
| 練習後 / 次の日 / 数日後・・・ / 大会当日 / 運命のドラフト当日・・・ | After Practice / Next Day / A Few Days Later... / Tournament Day / Fateful Draft Day... | Arial Rounded Bold, white in a navy outline (scene captions) |
| 月 (month banner) | Mo | Arial Rounded Bold, slanted like the numeral in front of it |
| 投手 捕手 一塁手 二塁手 三塁手 遊撃手 外野手 | Pitcher, Catcher, 1st Base, 2nd Base, 3rd Base, Shortstop, Outfield; short P, C, 1B, 2B, 3B, SS, OF | Arial Rounded Bold in the plate colours |
| 変更前 / 変更後 | Before / After | Arial Rounded Bold (Equip page) |
| スライダー系 カーブ系 フォーク系 シンカー系 シュート系 ストレート系 | Slider, Curve, Fork, Sinker, Shuuto, Fastball | as the item term sheet |
| セ・リーグ / パ・リーグ / レ・リーグ | Central League / Pacific League / Rev. League | Arial Narrow Bold on the plate |
| 巨人 中日 広島 ヤクルト 横浜 阪神 楽天 日本ハム 西武 オリックス ロッテ ソフトバンク | Giants, Chunichi, Hiroshima, Yakult, Yokohama, Hanshin, Rakuten, Nippon-Ham, Seibu, Orix, Lotte, SoftBank | the Japanese short forms, as in the glossary |
| パワフルズ カイザース キャットハンズ やんきーズ バルカンズ バスターズ | Powerfuls, Kaisers, Cathands, Yankiis, Vulcans, Busters | |
| 役職 / 平社員 / 係長 / 課長 | Post / Rank & File / Kakaricho / Kacho | Arial Rounded Bold, in the three colourings of the Japanese plates |
| 対戦 サクセス マイライフ ホームラン競争 アレンジ データあれこれ サウンド リモパワ ペナント 野球教室 応援曲 (main menu buttons) | Exhibition, Success, My Life, Home Run Derby, Arrange, My Data, Sound, Remo-Pawa, Pennant, Baseball School, Cheer Songs | Arial Rounded Bold in each button's own colours (`SMDL_TOP.rom`); My Data as in MLB Power Pros |

Practice menu (scs_rens.arc), tag font: 筋力 Weights, 打撃 Batting, 走塁 Running, 守備 Fielding, 精神 Mental,
スタミナ Stamina, 球速 Velocity, 変化球 Breaking, 走り込み Roadwork, コントロール Control, 投球 Pitching,
捕球 Catching, ペッパー Pepper, 肩力 Arm, ミーティング Meeting, 特別変化球 Sp. Break, 特別打撃 Sp. Bat,
巧打力 Contact, 長打力 Power; 故障率 Injury, 評価 Rating.

Training gear, the name shown next to "Lv." in the practice menu (scs_rens.arc, bank y5_rkz_0), set in
Arial Narrow Bold on the page's own grey ramp. The same names go into the script constants of
scs_main.rel and the level table of scs_rens.rel, so a sentence and the menu agree.

| Japanese | English | | Japanese | English |
|---|---|---|---|---|
| ダンベル / バーベル / ベンチプレス | Dumbbell / Barbell / Bench Press | | 竹バット / おもりバット / バッティングマシン | Bamboo Bat / Weighted Bat / Batting Machine |
| タイヤ / ３連タイヤ / パラシュート | Tire / Triple Tire / Parachute | | チューブ / 極太チューブ / ラットマシン | Tube / Thick Tube / Lat Machine |
| 鉄ゲタ / ミニローラー / ローラー | Iron Geta / Mini Roller / Roller | | タオル / ギブス / マッスラー | Towel / Brace / Muscler |
| 的当て・２×２ (３×３, ４×４) | Target 2x2 (3x3, 4x4) | | むにむにボール / 改 / 究極の変化球ボール | Squishy Ball / Squishy Ball+ / Ultimate Breaking Ball |
| 守備用ネット / 豪華守備用ネット / ノックマシン | Fielding Net / Deluxe Fielding Net / Fungo Machine | | 癒し系音楽 / アロマテラピー / リラックスカプセル | Calm Music / Aromatherapy / Relax Capsule |

A name has to fit the plate the game sizes from the Japanese name: about 12 pixels per Japanese
character plus 19. That is why 癒し系音楽 is "Calm Music" and not "Soothing Music". ミゾット, the maker's
name in front of the level 3 gear, stays "Mizotto".

Pitch names on the HUD use MLB Power Pros 2008's English names, shortened where the Japanese is short:

| Japanese | English | | Japanese | English |
|---|---|---|---|---|
| ストレート | Fastball | | ツーシーム | 2-Seamer |
| スライダー / Hスライダー / Vスライダー | Slider / Hard Slider / V-Slider | | カットボール | Cutter |
| カーブ / スローカーブ / ドロップカーブ / ナックルカーブ | Curve / Slow Curve / Drop Curve / Knuckle Curve | | スラーブ | Slurve |
| フォーク / SFF | Fork / Splitter | | パーム / ナックル | Palm / Knuckle |
| シンカー / Hシンカー / スクリュー | Sinker / Hard Sinker / Screwball | | チェンジアップ / サークルチェンジ | Changeup / Circle Change |
| シュート / Hシュート / カミソリシュート | Shuuto / Hard Shuuto / Razor Shuuto | | ドロップ / スローボール | Drop / Slow Ball |
| オリジナル | Original | | ヨネボール / ヨシボール / エモボール | Yone Ball / Yoshi Ball / Emo Ball |

"Shuuto" is the spelling of the English games (not Hepburn "shuto"). H is 高速: "Hard", as in MLB.

Data screen (scs_data.arc, scs_sys.arc), Arial Rounded Bold in the colours of the Japanese labels:

| Japanese | English |
|---|---|
| 個人データ / 仲間データ / 周りの評価 / スケジュール | My Data / Teammates / Ratings / Schedule (titles and buttons) |
| 装備変更 / アイテムリスト / システム / セーブしておわる / あきらめる | Equip / Item List / System / Save & Quit / Give Up |
| 投手能力 / 野手能力 / その他能力 / 自分の状態 | Pitcher / Fielder / Other / Status |
| 全て / 得意練習 / その他 (team-mate list) | All / Practice / Other |
| 利き腕 / フォーム / 成長タイプ / 調子 | B/T / Form / Growth / Cond. |
| 右投右打 ... 左投両打 | R/R, L/R, S/R, R/L, L/L, S/L: bats / throws, the English order (Japanese: throws, bats) |
| 評価メッセージ | Comments |
| 装備中アイテム / 練習道具 | Equipment / Accessories |
| column headers | TOP SPD, CTRL, STAM; TRJ, CON, PWR, SPD, ARM, FLD, E RES; practices: WGT, BAT, RUN, ARM, FLD, MNTL, STAM, VELO, CTRL, BRK (32 pixels a column) |
| 監督兼社長 / 監督 / 部長 / チームメイト / スカウト | Kantoku & Shacho / Kantoku / Bucho / Teammates / Scout |
| オーバースロー / スリークォーター / サイドスロー / アンダースロー | Overhand / 3-Quarters / Sidearm / Submarine (MLB) |
| トルネード / マサカリ / UFO | Tornado / Masakari / UFO |
| スタンダード / オープン / バスター / クラウチング / 一本足 | Standard / Open / Fake Bunt / Crouching / Flamingo (MLB) |
| 振り子 / 神主 / 天秤 / コンニャク / 個性的 / オリジナル / マニュアル | Pendulum / Kannushi / Tenbin / Konnyaku / Unique / Original / Manual |
| 先発 / 中継 / 抑え / 万能 / 俊足 / 巧打 / 豪打 / 堅守 タイプ | Starter / Reliever / Closer / All-Rounder / Speedster / Contact / Slugger / Defense (MLB) |
| 肩爆弾 / ひじ爆弾 / 足爆弾 | Shoulder / Elbow / Leg (the bomb is drawn next to the word) |
| 不眠症 / サボりぐせ / モテモテ / 恋の病 / 虫歯 / 爪割れ / カゼ | Insomnia / Laziness / Heartthrob / Lovesick / Cavity / Cracked Nail / Cold |
| センス○ / センス× / 買い物上手 / ボンボン / 野球バカ | Gd Sense / Pr Sense / Smart Shopper / Rich Kid / Baseball Nut |
| 熱血漢 / ふぬけ / ラッキーボーイ / アピール上手 / いいやつ | Hot-Blooded / Listless / Lucky Boy / Showman / Good Guy |
| 寝坊 / 出無精 / 弱気 / 仕事人間 / 世渡り上手 | Oversleeper / Homebody / Timidity / Workaholic / Smooth Talker |

Signature forms keep their Japanese names (Masakari, Kannushi, Tenbin, Konnyaku), like Koshien and bento. MLB Power Pros
called 神主 "Loose" and 振り子 "Bat Wavin"; neither says what the stance is.

Ability plates (are_abi.arc, 248 names). The book abilities use the names of the item term sheet, letter for
letter. Names from MLB Power Pros 2008's plate sheet: Starter, Swing Man (先発中継), Middle Reliever, Closer,
Mop-up Man (敗戦処理), SIT. Lefty (左のワンポイント), Pinch Hitter, Pinch Runner, DEF Replcmnt (守備要員),
DEF Liability (途中交代), Gd / Pr Home, Road, Day Game, Night Game, Gd Rain (雨男), All Star (お祭り男),
Summer Star (夏男). Worded for the patch:

| Japanese | English |
|---|---|
| 慎重走塁 / 持続 / バント◎ / 弱気 / 筋肉痛 | Cautious Run / Staying Power / Grt Bunt / Timidity / Sore Muscles |
| ～消す (Boost screen) | Remove + the ability, on two lines |
| ささやきやぶり / 絶好調男 / がんばり屋さん | Talk-Proof / Mr. Top Form / Hard Worker |
| 闘気 / 奪力 / 神速 / 豪力 / 緊縛 | Fighting Aura / Power Drain / Godspeed / Brute Force / Lockdown |
| 鉄腕 / 剛球 / 絶倫 / 呪縛 / 気迫 | Iron Arm / Power Ball / Tireless / Hex / Grit |
| 青い稲妻 / ガソリンタンク / 鉄人 / 鉄仮面 / 安打製造機 | Blue Lightning / Gas Tank / Iron Man / Iron Mask / Hit Machine |
| 牛若丸 / スーパーカートリオ / 怪童 / 精密機械 | Ushiwakamaru / Supercar Trio / Wonder Boy / Precision Machine |
| ブンブン丸 / バックスクリーン男 / 代打の神様 / ドクターK | Free Swinger / Mr. Backscreen / Pinch-Hit God / Doctor K (奪三振 is Dr. K) |
| おまかせ / 完投 / 調子次第 / スタミナ限界 / スタミナ温存 / 勝利投手 | Auto / Complete Game / By Condition / Stamina Limit / Save Stamina / Winning P |
| リード時 / 中継ぎエース / ビハインドでも / 守護神 / セーブ狙い / 接戦時 / 先発適性 | When Ahead / Relief Ace / Even Behind / Stopper / Save Chance / Close Games / Starter Fit |
| シリーズ男 / 逆シリーズ男 / シリーズ最強男 | Mr. Series / Series Slump / Series Legend (not MLB's Mr. October, Mr. May) |
| 春男 / 秋男 / 4月男 ... 9月男 / 伝説の夏男 / 伝説のお祭り男 | Spring Star / Fall Star / April Star ... Sept. Star / Summer Legend / All Star Legend |
| アベック砲 / 最強アベック砲 / 援護射撃 / ミスター2ラン | Slugger Duo / Top Slugger Duo / Run Support / Mr. 2-Run |
| ドーム / 野外 / 交流戦 / サンデー / 初対決 / 外国人 / 先頭打者 ○× | Gd / Pr Dome, Outdoors, Interleague, Sunday, 1st Meeting, vs. Imports, Leadoff |
| ストレート / 変化球 ○× / 古巣に強い / 古巣に弱い | Gd / Pr Fastball, Brk Ball / Gd vs. Ex-Team / Pr vs. Ex-Team |
| 巨人 ... キラー | Giants, Chunichi, Hiroshima, Swallows, Yokohama, Hanshin, Orix, Nippon-Ham, Seibu, Kintetsu, Lotte, Daiei, Lions (レオ), Yakult, BlueWave (青波), Rakuten, Hawks, SoftBank + Killer |
| 打撲 / ねんざ / 腰痛 / 脇腹痛 / 突き指 / 肩痛 / 肘痛 / 肉離れ | Bruise / Sprain / Back Pain / Side Pain / Stubbed Finger / Shoulder Pain / Elbow Pain / Pulled Muscle |
| アキレス腱痛 / 断裂 / 頬骨骨折 / 鎖骨骨折 / ヒザ靭帯断裂 / ギックリ腰 / リュウマチ | Achilles Pain / Achilles Tear / Broken Cheekbone / Broken Collarbone / Torn Knee Ligament / Strained Back / Rheumatism |
| 投球位置右 / 投球位置左 | Rubber: Right / Rubber: Left |

What 持続 and the ○ / × of ストレート and 変化球 do in play was not checked; the English follows the words.

Shop and item list (scs_item.arc; the item list is in scs_main.arc), Arial Rounded Bold in the colours of the Japanese labels:

| Japanese | English |
|---|---|
| ショップ / 所持金 / 説明 | Shop (Arial Black, slanted) / Money / Info |
| 全ての商品 / ボール / バット / グラブ / スパイク / その他 | All Items / Balls / Bats / Gloves / Spikes / Other |
| OK / キャンセル | OK (as drawn) / Cancel |
| 購入 / 所持 (behind a count) | Buy / Own: `x1 Buy`, `x3 Own` (24 pixels each) |
| 購入済 / 取得済 / 売り切れ！ | Bought / Owned / Sold Out! |
| 全ての商品 / 練習道具 / その他 (larger tabs, not seen in game) | All Items / Accessories / Other (練習道具 is Accessories on the Data screen too) |
| 消費アイテム / その他 (item list) | Consumables / Other |
| 装備中 / アイテムリスト (equip pop-up) | Equipped / Item List |
| 円 | stays 円, as on the HUD |
| お買得！でやんす (Yabe's bubble) | stays: decided as a picture |

取得済 was not seen in game. "Owned" covers both readings (an ability already learned, an item already held).
Gear names on the item icons (not seen in game): the term sheet's names without the kind of gear, 40 pixels wide:
Catching, No-Miss, S No-Miss, Pro, Contact, Impact, Power, S Power, Mighty, Pro Power, Lock-On, Sweet, Running,
Dig-In, Pitching, S Pitching, Heavy, S Heavy, Pro Pitch, Sniper, S Sniper, Pro Sniper.

System settings list (scs_sys.arc), the wording of the screen's own help lines (rumble, catcher window, voice):

| Japanese | English |
|---|---|
| 試合中のコントローラ設定 / 投球/打撃画面 / 音声設定 | In-Game Controls / Pitching / Batting / Voice |
| イベントの振動 / メッセージのショートカット / サポートメッセージ | Event Rumble / Message Shortcut / Help Messages |
| Aタイプ / Bタイプ / 振動あり / 振動なし | Type A / Type B / Rumble On / Rumble Off |
| 設定中 / 設定していません / ON / OFF | Set / Not Set / ON / OFF (as drawn) |
| ウインドウなし / ウインドウあり / 投手視点 | No Window / Window / Pitcher View |
| 十字ボタン / コントロールスティック / Lスティック | +Control Pad / Control Stick / L Stick (Nintendo's names) |
| 難度 / ノーマル / ルーキー | Difficulty / Normal / Rookie |

Schedule (scs_data.rel, strings that the build lays out again; all 24 share 444 bytes, so the tournament rounds stay
short): Practice Game; Intercity Qual R1 / SF / Final; Intercity Natl SF / Final; Japan Champ Qual R1 / Final;
Japan Champ Natl SF / Final; Elite Squad Camp; Elite Squad Camp Game; Welcome Ceremony (入社式); CEO New Year Edict;
Closing of the Books (決算, the glossary term); Exam; Exam, Japan Champ Qual Final (the week that has both: this
order lets the two entries share their letters); Contract Renewal; Club Dues (部費); Summer Festival; Christmas;
New Year's; Valentine's Day; Industrial & College Draft. Date column: `9 Mo 3 Wk`, as on the HUD.

Still Japanese on these pages: プログラム, テキスト, 特別ルーム (not met in scenario 1; meaning to be
confirmed in play before they are worded).
