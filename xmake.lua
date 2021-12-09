add_rules("mode.debug", "mode.release")

if is_mode("debug") then
    add_cflags("-g", "-fno-pic", "-no-pie", "-fsanitize=address")
    add_ldflags("-fno-pic", "-no-pie", "-fsanitize=address")
end

target("deadcheck")
    set_kind("binary")
    add_includedirs("src/include")
    add_files("src/*.c")