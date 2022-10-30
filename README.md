# parakeet-crypto-rs

使用 Rust 重新实现 [Parakeet][project_parakeet] 所支持的算法。

## 目前已实现的算法

- QMCv1 (static_map)
- QMCv2 (map / rc4)

## 命令行调用

<details>
  <summary>查看详细</summary>

为了方便测试，库内置了一个命令行。如果你知道你在干什么，你可以利用命令行来进行批量转码。

你可以通过命令行来指定密钥以及解密文件参数，以下是几个解码仓库内的实例文件的调用方法展示：

```sh
# QMCv1: 支持 key58 或 key128
cargo run --release qmc1 --static-key "@qmc1_key58.bin" "sample/test_qmc1.qmcogg" "decrypted.ogg"
cargo run --release qmc1 --static-key "base64://4BAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fICEiIyQlJicoKSorLC0uLzAxMjM0NTY3OA==" "sample/test_qmc1.qmcogg" "decrypted.ogg"

# QMCv2: 支持 EncV2
cargo run --release qmc2 --seed 123 --key1 "base64:CwwNDg8QERIVFhcYGRobHA==" --key2 "base64:HyAhIiMkJSYpKissLS4vMA==" "sample/test_qmc2_rc4_EncV2.mgg" "decrypted.ogg"
cargo run --release qmc2 --seed 123 "sample/test_qmc2_rc4.mgg" "decrypted.ogg"
cargo run --release qmc2 --seed 123 "sample/test_qmc2_map.mgg" "decrypted.ogg"
```

请注意：

- 上述例子中的密钥为测试用的密钥，与流媒体软件的生产密钥不一致。
- 你可以使用 `base64:` 直接描述密钥，或 `@文件名` 来从文件读取密钥。

</details>

## 声明

> 我们 "Parakeet-RS 小组" 不支持亦不提倡盗版。
> 我们认为人们能够选择如何享用购买的内容。
> 小鹦鹉软件的使用者应保留解密后的副本仅做个人使用，而非进行二次分发。
> 因使用该软件产生的任何问题都与软件作者无关。
>
> We "Team Parakeet-RS" do not endorse nor encourage piracy.
> We believe that people should have a choice when consuming purchased content.
> Parakeet users should keep their decrypted copies for private use, not to re-distribute them.
> We are not liable for any damage caused by the use of this software.

[project_parakeet]: https://github.com/jixunmoe/parakeet
