add_rules("mode.debug", "mode.release")

if is_mode("release") then
    add_cflags("-O2")
    add_ldflags("-O2")
elseif is_mode("debug") then
    add_cflags("-g", "-fno-pic", "-no-pie", "-fsanitize=address")
    add_ldflags("-fno-pic", "-no-pie", "-fsanitize=address")
end

target("echeck")
    set_kind("binary")
    add_includedirs("src/include")
    add_files("src/*.c")