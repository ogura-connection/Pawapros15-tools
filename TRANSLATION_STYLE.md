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
| ノビ / ジャイロボール | Fastball Life / Spin | MLB Power Pros names |
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
| 役職 / 平社員 / 係長 / 課長 | Post / Rank & File / Kakaricho / Kacho | Arial Rounded Bold, in the three colourings of the Japanese plates |

Practice menu (scs_rens.arc), tag font: 筋力 Weights, 打撃 Batting, 走塁 Running, 守備 Fielding, 精神 Mental,
スタミナ Stamina, 球速 Velocity, 変化球 Breaking, 走り込み Roadwork, コントロール Control, 投球 Pitching,
捕球 Catching, ペッパー Pepper, 肩力 Arm, ミーティング Meeting, 特別変化球 Sp. Break, 特別打撃 Sp. Bat,
巧打力 Contact, 長打力 Power; 故障率 Injury, 評価 Rating.

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

Still Japanese on these pages: プログラム, テキスト, 特別ルーム (not met in scenario 1; meaning to be
confirmed in play before they are worded).
